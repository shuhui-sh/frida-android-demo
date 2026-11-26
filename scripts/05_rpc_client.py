# -*- coding: utf-8 -*-
"""
场景五：算子黑盒化 —— 用 NativeFunction + rpc.exports 从 Python 直接调用手机内存里的算子
前置条件：目标 App (com.demo.reajiagu) 已在手机上运行，且设备端已启动 frida-server
用法：python scripts/05_rpc_client.py
"""
import frida

PKG = "com.demo.reajiagu"

JS_CODE = r"""
'use strict';

var fnvAddr = Module.findExportByName('libreajiagu.so', 'computeFnv1a32');
var fnv1aFunc = new NativeFunction(fnvAddr, 'uint32', ['pointer', 'ulong']);

rpc.exports = {
    // 直接调用 C++ 内存算子 computeFnv1a32(const char* data, size_t len)
    callfnv1a: function (text) {
        var buf = Memory.allocUtf8String(text);
        var h = fnv1aFunc(buf, text.length); // 针对 ASCII 输入；若含中文需按 UTF-8 字节长度传参
        return '0x' + ('00000000' + (h >>> 0).toString(16).toUpperCase()).slice(-8);
    },
    // 直接调用 JNI 签名方法 NativeBridge.signPayloadNative(String, long)
    callsign: function (payload, ts) {
        var result = null;
        Java.performNow(function () {
            var NB = Java.use('com.demo.reajiagu.NativeBridge');
            result = NB.signPayloadNative(payload, ts);
        });
        return result;
    }
};
"""


def find_or_spawn_pid(device: frida.core.Device, pkg: str) -> int:
    for app in device.enumerate_applications():
        if app.identifier == pkg and app.pid > 0:
            return app.pid
    pid = device.spawn([pkg])
    device.resume(pid)
    import time
    time.sleep(2.0)
    return pid


def main():
    device = frida.get_usb_device(timeout=10)
    pid = find_or_spawn_pid(device, PKG)
    session = device.attach(pid)
    script = session.create_script(JS_CODE)
    script.load()

    for sample in [
        "REA-2026-PRO",
        "FRIDA-HACK99",
        "CG_AUTH:com.demo.reajiagu:shield_cloudgame_demo:20261026|ts=20261026",
    ]:
        h = script.exports_sync.callfnv1a(sample)
        print(f"[RPC/NativeFunction] computeFnv1a32({sample!r}) => {h}")

    for ts in [1730000001, 1730000002, 1730000003]:
        sig = script.exports_sync.callsign(f"CG_AUTH:{PKG}:shield_cloudgame_demo:{ts}", ts)
        print(f"[RPC/JNI] signPayloadNative(ts={ts}) => {sig}")

    script.unload()
    session.detach()


if __name__ == "__main__":
    main()
