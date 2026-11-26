'use strict';

/**
 * 场景四：Native Interceptor 返回值篡改与鉴权绕过
 * 运行方式（Attach 到已运行的靶场 App，然后在界面输入任意无效激活码点击校验）：
 *   frida -U -n "REA 加固逆向靶场" -l scripts/04_bypass_license.js
 * 或 Spawn 启动：
 *   frida -U -f com.demo.reajiagu -l scripts/04_bypass_license.js
 */
function installBypass() {
    var verifyAddr = Module.findExportByName(
        'libreajiagu.so',
        'Java_com_demo_reajiagu_NativeBridge_verifyLicenseCodeNative'
    );
    if (!verifyAddr) {
        return false;
    }

    Interceptor.attach(verifyAddr, {
        onLeave: function (retval) {
            var orig = retval.toInt32();
            if (orig === 0) {
                retval.replace(ptr(1)); // 将 JNI_FALSE (0) 篡改为 JNI_TRUE (1)
                console.log('[BYPASS/JNI] verifyLicenseCodeNative: 0 (JNI_FALSE) -> 1 (JNI_TRUE)');
            }
        }
    });
    console.log('[*] Bypass installed on verifyLicenseCodeNative @ ' + verifyAddr);
    return true;
}

if (!installBypass()) {
    // 若为 Spawn 启动且 SO 尚未加载，等 Java 层首次触发后再挂钩
    Java.perform(function () {
        var NativeBridge = Java.use('com.demo.reajiagu.NativeBridge');
        NativeBridge.verifyLicenseCodeNative.implementation = function (code) {
            installBypass();
            return this.verifyLicenseCodeNative(code);
        };
    });
}
