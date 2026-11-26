'use strict';

/**
 * 场景三：Native 符号枚举、.rodata 内存扫描与底层 C++ 算子拦截
 * 运行方式：
 *   frida -U -f com.demo.reajiagu -l scripts/03_native_memscan.js
 */
var installed = false;

function inspectAndHookNative() {
    if (installed) return;
    var mod = Process.findModuleByName('libreajiagu.so');
    if (!mod) return;
    installed = true;

    console.log('[MODULE] libreajiagu.so base=' + mod.base + ' size=' + mod.size);

    // 1. 枚举业务相关导出符号与相对偏移
    mod.enumerateExports().forEach(function (exp) {
        if (exp.name.indexOf('Java_com_demo_reajiagu') === 0 || exp.name.indexOf('computeFnv1a32') >= 0) {
            console.log(
                '[EXPORT] ' + exp.type + ' ' + exp.name + ' @ ' + exp.address
                + ' (offset +0x' + exp.address.sub(mod.base).toString(16) + ')'
            );
        }
    });

    // 2. 在模块内存空间扫描 .rodata 中的静态盐值特征（ASCII "REA_NATI"）
    var hits = Memory.scanSync(mod.base, mod.size, '52 45 41 5f 4e 41 54 49');
    hits.forEach(function (hit) {
        var dump = hexdump(hit.address, { offset: 0, length: 32, header: false, ansi: false });
        console.log(
            '[MEMSCAN] 命中 kSecretSalt @ ' + hit.address
            + ' (offset +0x' + hit.address.sub(mod.base).toString(16) + ') => "'
            + hit.address.readUtf8String(16) + '"\n' + dump
        );
    });

    // 3. 拦截底层 C++ 算子 computeFnv1a32(const char* data, size_t len)
    var fnvAddr = Module.findExportByName('libreajiagu.so', 'computeFnv1a32');
    if (fnvAddr) {
        Interceptor.attach(fnvAddr, {
            onEnter: function (args) {
                this.len = args[1].toInt32();
                this.inputStr = args[0].readUtf8String(this.len);
            },
            onLeave: function (retval) {
                var hashVal = retval.toUInt32();
                console.log(
                    '[NATIVE/computeFnv1a32] len=' + this.len
                    + ' input="' + this.inputStr + '" => hash=0x'
                    + ('00000000' + hashVal.toString(16).toUpperCase()).slice(-8)
                );
            }
        });
    }
}

Java.perform(function () {
    // 借 System.loadLibrary 或首次调用 NativeBridge 时机，确保 libreajiagu.so 已加载
    var TokenEngine = Java.use('com.demo.reajiagu.TokenEngine');
    TokenEngine.generateBootToken
        .overload('java.lang.String', 'long')
        .implementation = function (pkg, seed) {
            var ret = this.generateBootToken(pkg, seed);
            inspectAndHookNative();
            return ret;
        };

    console.log('[*] 03_native_memscan.js loaded');
});
