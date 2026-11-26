# -*- coding: utf-8 -*-
r"""
Frida 真机靶场全链路实测驱动脚本
依赖: frida (需与设备端 frida-server 版本一致) + adb
目标: com.demo.reajiagu (libreajiagu.so)
用法: python scripts/frida_full_suite.py [--serial <adb_serial>]
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path
import frida

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PKG = "com.demo.reajiagu"
ROOT_DIR = Path(__file__).resolve().parent.parent
IMG_DIR = ROOT_DIR / "screenshots"
IMG_DIR.mkdir(parents=True, exist_ok=True)

JS_AGENT = r"""
'use strict';

function sendLog(tag, msg) {
    send({ type: 'log', tag: tag, msg: String(msg) });
}

function getJavaStack(maxFrames) {
    var limit = maxFrames || 8;
    var out = [];
    try {
        var Throwable = Java.use('java.lang.Throwable');
        var frames = Throwable.$new().getStackTrace();
        for (var i = 0; i < frames.length && i < limit; i++) {
            out.push('    [J#' + i + '] ' + frames[i].toString());
        }
    } catch (e) {
        out.push('    [J#err] ' + e);
    }
    return out.join('\n');
}

function getNativeStack(ctx, maxFrames) {
    var limit = maxFrames || 8;
    var out = [];
    if (!ctx) return '    (no context)';
    try {
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        for (var i = 0; i < bt.length && i < limit; i++) {
            var addr = bt[i];
            var mod = Process.findModuleByAddress(addr);
            var sym = DebugSymbol.fromAddress(addr);
            var loc = mod ? (mod.name + '+0x' + addr.sub(mod.base).toString(16)) : addr.toString();
            out.push('    [N#' + i + '] ' + addr + ' ' + loc + (sym && sym.name ? ' (' + sym.name + ')' : ''));
        }
    } catch (e) {
        out.push('    [N#err] ' + e);
    }
    return out.join('\n');
}

var bypassEnabled = false;
var nativeHooksInstalled = false;
var fnv1aFunc = null;

function installNativeHooks() {
    if (nativeHooksInstalled) return;
    var mod = Process.findModuleByName('libreajiagu.so');
    if (!mod) return;
    nativeHooksInstalled = true;

    sendLog('MODULE', 'libreajiagu.so base=' + mod.base + ' size=' + mod.size + ' path=' + mod.path);

    // 1. 枚举导出符号
    var exports = mod.enumerateExports();
    exports.forEach(function (exp) {
        if (exp.name.indexOf('Java_com_demo_reajiagu') === 0 || exp.name.indexOf('computeFnv1a32') >= 0) {
            sendLog('EXPORT', exp.type + ' ' + exp.name + ' @ ' + exp.address + ' (offset +0x' + exp.address.sub(mod.base).toString(16) + ')');
        }
    });

    // 2. 内存扫描 .rodata 段提取 16 字节盐值 kSecretSalt ("REA_NATIVE_KEY_9")
    var pattern = '52 45 41 5f 4e 41 54 49'; // "REA_NATI"
    var hits = Memory.scanSync(mod.base, mod.size, pattern);
    hits.forEach(function (hit) {
        var dump = hexdump(hit.address, { offset: 0, length: 32, header: false, ansi: false });
        var ascii = hit.address.readUtf8String(16);
        sendLog('MEMSCAN', '命中 kSecretSalt @ ' + hit.address + ' (offset +0x' + hit.address.sub(mod.base).toString(16) + ') => "' + ascii + '"\n' + dump);
    });

    // 3. Interceptor 拦截底层 C++ 算子 computeFnv1a32(const char* data, size_t len)
    var fnvAddr = Module.findExportByName('libreajiagu.so', 'computeFnv1a32');
    if (fnvAddr) {
        fnv1aFunc = new NativeFunction(fnvAddr, 'uint32', ['pointer', 'ulong']);
        Interceptor.attach(fnvAddr, {
            onEnter: function (args) {
                this.len = args[1].toInt32();
                this.inputStr = args[0].readUtf8String(this.len);
            },
            onLeave: function (retval) {
                var hashVal = retval.toUInt32();
                sendLog('NATIVE/computeFnv1a32', 'len=' + this.len + ' input="' + this.inputStr + '" => hash=0x' + ('00000000' + hashVal.toString(16).toUpperCase()).slice(-8));
            }
        });
    }

    // 4. Interceptor 拦截 JNI 函数 verifyLicenseCodeNative，支持动态篡改返回值并输出混合栈
    var verifyAddr = Module.findExportByName('libreajiagu.so', 'Java_com_demo_reajiagu_NativeBridge_verifyLicenseCodeNative');
    if (verifyAddr) {
        Interceptor.attach(verifyAddr, {
            onEnter: function (args) {
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                var orig = retval.toInt32();
                if (bypassEnabled && orig === 0) {
                    retval.replace(1);
                    sendLog('BYPASS/JNI', 'verifyLicenseCodeNative 原始返回=' + orig + ' (JNI_FALSE) -> 已篡改为 1 (JNI_TRUE)');
                } else {
                    sendLog('NATIVE/JNI', 'verifyLicenseCodeNative 返回=' + orig + '\n  -- Native Backtrace --\n' + getNativeStack(this.ctx, 5));
                }
            }
        });
    }
}

Java.perform(function () {
    var TokenEngine = Java.use('com.demo.reajiagu.TokenEngine');

    // Hook 1: 拦截 XOR 字符串还原函数
    TokenEngine.deobfuscatePrefix.implementation = function () {
        var ret = this.deobfuscatePrefix();
        sendLog('JAVA/XOR', 'TokenEngine.deobfuscatePrefix() => "' + ret + '"');
        return ret;
    };

    // Hook 2: 拦截启动/动态 Token 生成
    TokenEngine.generateBootToken.overload('java.lang.String', 'long').implementation = function (pkg, seed) {
        installNativeHooks();
        var t0 = Date.now();
        var ret = this.generateBootToken(pkg, seed);
        sendLog('JAVA/Token', 'generateBootToken(pkg="' + pkg + '", seed=' + seed + ') => "' + ret.trim() + '" (' + (Date.now() - t0) + 'ms)');
        return ret;
    };

    // Hook 3: 拦截 VIP 订单与激活码校验
    TokenEngine.verifyVipOrder.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (uid, code, amount) {
        installNativeHooks();
        var ret = this.verifyVipOrder(uid, code, amount);
        sendLog('JAVA/Verify', 'verifyVipOrder(userId="' + uid + '", code="' + code + '", amount=' + amount + ') => VIP_LEVEL=' + ret + '\n  -- Java StackTrace --\n' + getJavaStack(6));
        return ret;
    };

    sendLog('INIT', 'Java 层 Hook 安装完毕');
});

function triggerUiVerify(inputCode) {
    Java.perform(function () {
        Java.choose('com.demo.reajiagu.MainActivity', {
            onMatch: function (activity) {
                Java.scheduleOnMainThread(function () {
                    try {
                        var TextView = Java.use('android.widget.TextView');
                        var Button = Java.use('android.widget.Button');
                        var ViewGroup = Java.use('android.view.ViewGroup');
                        var StringCls = Java.use('java.lang.String');

                        var content = activity.findViewById(0x01020002); // android.R.id.content
                        var vg = Java.cast(content, ViewGroup);
                        var rootLayout = Java.cast(vg.getChildAt(0), ViewGroup);

                        var editView = Java.cast(rootLayout.getChildAt(3), TextView);

                        editView.setText.overload('java.lang.CharSequence').call(editView, StringCls.$new(inputCode));
                        sendLog('UI', '已在主线程填入激活码 "' + inputCode + '"');
                    } catch (e) {
                        sendLog('UI/ERR', String(e));
                    }
                });
            },
            onComplete: function () {}
        });
    });
}

rpc.exports = {
    enablebypass: function (flag) {
        bypassEnabled = !!flag;
        return bypassEnabled;
    },
    uiverify: function (code) {
        triggerUiVerify(code);
        return 'ok';
    },
    callsign: function (payload, ts) {
        var result = null;
        Java.performNow(function () {
            var NB = Java.use('com.demo.reajiagu.NativeBridge');
            result = NB.signPayloadNative(payload, ts);
        });
        return result;
    },
    callfnv1a: function (text) {
        installNativeHooks();
        if (!fnv1aFunc) return 'ERR_NO_FUNC';
        var buf = Memory.allocUtf8String(text);
        var h = fnv1aFunc(buf, text.length);
        return '0x' + ('00000000' + (h >>> 0).toString(16).toUpperCase()).slice(-8);
    }
};
"""

def adb_cmd(serial: str | None, *args: str) -> list[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    return cmd

def screencap(serial: str | None, out_path: Path):
    with open(out_path, "wb") as f:
        subprocess.run(adb_cmd(serial, "exec-out", "screencap", "-p"), stdout=f, check=True)
    print(f"[*] Screenshot saved: {out_path.name} ({out_path.stat().st_size} bytes)", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Frida 真机靶场全链路自动化验证脚本")
    parser.add_argument("--serial", default=None, help="指定 ADB 设备序列号（默认自动连接 USB 设备）")
    args = parser.parse_args()

    dev = frida.get_device(args.serial, timeout=10) if args.serial else frida.get_usb_device(timeout=10)
    serial = args.serial or dev.id
    print(f"[*] Connected to device: {dev.name} ({dev.id})", flush=True)

    pid = dev.spawn([PKG])
    print(f"[*] Spawned {PKG} (PID={pid})", flush=True)
    session = dev.attach(pid)

    script = session.create_script(JS_AGENT)
    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg.get("payload", {})
            if isinstance(p, dict) and p.get("type") == "log":
                print(f"[{p['tag']}] {p['msg']}", flush=True)
            else:
                print(f"[SEND] {p}", flush=True)
        elif msg.get("type") == "error":
            print(f"[ERROR] {msg.get('stack') or msg.get('description')}", flush=True)

    script.on("message", on_message)
    script.load()
    dev.resume(pid)
    time.sleep(2.5)
    screencap(serial, IMG_DIR / "01_baseline_ui.png")

    print("\n=== Phase 1: 未开启篡改，测试无效激活码 FRIDA-HACK99 ===", flush=True)
    script.exports_sync.enablebypass(False)
    script.exports_sync.uiverify("FRIDA-HACK99")
    time.sleep(0.5)
    subprocess.run(adb_cmd(serial, "shell", "input", "tap", "540", "935"), check=True)
    time.sleep(1.2)
    screencap(serial, IMG_DIR / "02_rejected_ui.png")

    print("\n=== Phase 2: 开启 Native Interceptor 返回值篡改，再次校验 FRIDA-HACK99 ===", flush=True)
    script.exports_sync.enablebypass(True)
    script.exports_sync.uiverify("FRIDA-HACK99")
    time.sleep(0.5)
    subprocess.run(adb_cmd(serial, "shell", "input", "tap", "540", "935"), check=True)
    time.sleep(1.2)
    screencap(serial, IMG_DIR / "03_bypassed_ui.png")

    print("\n=== Phase 3: Python Host 通过 Frida RPC 直接调用进程内 Native 算子 ===", flush=True)
    for sample in ["REA-2026-PRO", "FRIDA-HACK99", "CG_AUTH:com.demo.reajiagu:shield_cloudgame_demo:20261026|ts=20261026"]:
        h = script.exports_sync.callfnv1a(sample)
        print(f"[RPC/NativeFunction] computeFnv1a32({sample!r}) => {h}", flush=True)

    for ts in [1730000001, 1730000002, 1730000003]:
        sig = script.exports_sync.callsign(f"CG_AUTH:{PKG}:shield_cloudgame_demo:{ts}", ts)
        print(f"[RPC/JNI] signPayloadNative(ts={ts}) => {sig}", flush=True)

    script.unload()
    print("\n[*] All phases completed successfully.", flush=True)

if __name__ == "__main__":
    main()
