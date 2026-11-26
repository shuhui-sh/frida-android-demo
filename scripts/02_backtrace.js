'use strict';

/**
 * 场景二：跨界追踪 —— 同时拉取 Java 调用栈与 Native 调用栈
 * 运行方式：
 *   frida -U -f com.demo.reajiagu -l scripts/02_backtrace.js
 */
function getJavaStack(maxFrames) {
    var Throwable = Java.use('java.lang.Throwable');
    var frames = Throwable.$new().getStackTrace();
    var out = [];
    for (var i = 0; i < frames.length && i < (maxFrames || 6); i++) {
        out.push('    [J#' + i + '] ' + frames[i].toString());
    }
    return out.join('\n');
}

function getNativeStack(ctx, maxFrames) {
    var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    var out = [];
    for (var i = 0; i < bt.length && i < (maxFrames || 5); i++) {
        var addr = bt[i];
        var mod = Process.findModuleByAddress(addr);
        var sym = DebugSymbol.fromAddress(addr);
        var loc = mod ? (mod.name + '+0x' + addr.sub(mod.base).toString(16)) : addr.toString();
        out.push('    [N#' + i + '] ' + addr + ' ' + loc + (sym && sym.name ? ' (' + sym.name + ')' : ''));
    }
    return out.join('\n');
}

var nativeHooked = false;

function hookNativeVerify() {
    if (nativeHooked) return;
    var verifyAddr = Module.findExportByName(
        'libreajiagu.so',
        'Java_com_demo_reajiagu_NativeBridge_verifyLicenseCodeNative'
    );
    if (!verifyAddr) return;
    nativeHooked = true;

    Interceptor.attach(verifyAddr, {
        onEnter: function () {
            this.ctx = this.context;
        },
        onLeave: function (retval) {
            console.log(
                '[NATIVE/JNI] verifyLicenseCodeNative 返回=' + retval.toInt32()
                + '\n  -- Native Backtrace --\n' + getNativeStack(this.ctx, 5)
            );
        }
    });
}

Java.perform(function () {
    var TokenEngine = Java.use('com.demo.reajiagu.TokenEngine');
    TokenEngine.verifyVipOrder
        .overload('java.lang.String', 'java.lang.String', 'int')
        .implementation = function (uid, code, amount) {
            hookNativeVerify();
            var ret = this.verifyVipOrder(uid, code, amount);
            console.log(
                '[JAVA/Verify] verifyVipOrder(userId="' + uid + '", code="' + code + '", amount=' + amount + ')'
                + ' => VIP_LEVEL=' + ret
                + '\n  -- Java StackTrace --\n' + getJavaStack(6)
            );
            return ret;
        };

    console.log('[*] 02_backtrace.js loaded');
});
