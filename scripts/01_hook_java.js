'use strict';

/**
 * 场景一：Java 层方法拦截与混淆字符串还原
 * 运行方式（冷启动 Spawn 模式，确保拦截到 Application.onCreate 中的调用）：
 *   frida -U -f com.demo.reajiagu -l scripts/01_hook_java.js
 */
Java.perform(function () {
    var TokenEngine = Java.use('com.demo.reajiagu.TokenEngine');

    // 1. 拦截私有 XOR 还原方法，直接打印返回明文
    TokenEngine.deobfuscatePrefix.implementation = function () {
        var ret = this.deobfuscatePrefix();
        console.log('[JAVA/XOR] TokenEngine.deobfuscatePrefix() => "' + ret + '"');
        return ret;
    };

    // 2. 拦截指定重载的 generateBootToken(String, long)
    TokenEngine.generateBootToken
        .overload('java.lang.String', 'long')
        .implementation = function (pkg, seed) {
            var t0 = Date.now();
            var ret = this.generateBootToken(pkg, seed);
            console.log(
                '[JAVA/Token] generateBootToken(pkg="' + pkg + '", seed=' + seed + ')'
                + ' => "' + ret.trim() + '" (' + (Date.now() - t0) + 'ms)'
            );
            return ret;
        };

    console.log('[*] 01_hook_java.js loaded');
});
