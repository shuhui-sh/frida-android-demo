# Frida Android 动态插桩实战靶场 (`frida-android-demo`)

配套文章《Frida Android 逆向实战：从核心原理、上手配置到真机全链路分析》的可复现靶场工程，包含一个横跨 **Java 层混淆摘要** 与 **C++ JNI 层加盐哈希** 的 Android 演示 App，以及 5 个按场景拆分的独立 Frida 脚本和 1 个 Python 全链路自动化脚本。

## 一、工程目录结构

```text
frida-android-demo/
├── app/
│   ├── build.gradle.kts                         # Android + NDK/CMake 构建脚本 (applicationId: com.demo.reajiagu)
│   └── src/main/
│       ├── AndroidManifest.xml                  # 入口 Application: com.demo.reajiagu.DemoApplication
│       ├── java/com/demo/reajiagu/
│       │   ├── DemoApplication.java             # 启动时调用 TokenEngine.generateBootToken()
│       │   ├── MainActivity.java                # 靶场交互界面（展示 BootToken 与激活码实时校验）
│       │   ├── TokenEngine.java                 # Java 层核心业务（XOR 0x5A + SHA-256 + JNI 签名）
│       │   └── NativeBridge.java                # JNI 桥接类（System.loadLibrary("reajiagu")）
│       └── cpp/
│           ├── CMakeLists.txt                   # 编译 libreajiagu.so
│           └── native-lib.cpp                   # C++ 层加盐 FNV-1a 算子 computeFnv1a32 与 JNI 校验函数
├── apks/
│   └── frida-target.apk                         # 预编译的靶场 APK（支持 arm64-v8a / armeabi-v7a）
└── scripts/
    ├── 01_hook_java.js                          # 场景一：Java 层方法拦截与混淆字符串还原
    ├── 02_backtrace.js                          # 场景二：Java + Native 跨层调用栈回溯
    ├── 03_native_memscan.js                     # 场景三：Native 符号枚举、.rodata 内存扫描与底层算子拦截
    ├── 04_bypass_license.js                     # 场景四：Native Interceptor 返回值篡改与鉴权绕过
    ├── 05_rpc_client.py                         # 场景五：NativeFunction + rpc.exports 跨进程调用算子
    └── frida_full_suite.py                      # 一键串联全部场景的 Python 自动化驱动脚本
```

## 二、快速复现指南

### 1. 环境准备

- 一台已 Root 的 Android 手机（或带 Root 权限的模拟器），开启 USB 调试
- PC 端安装与设备端 `frida-server` 版本严格一致的 Frida：
  ```bash
  pip install frida==16.7.19 frida-tools==12.5.1
  ```
- 从 [Frida Releases](https://github.com/frida/frida/releases) 下载对应架构（如 `arm64`）的 `frida-server`，推送到手机并启动：
  ```bash
  adb push frida-server-16.7.19-android-arm64 /data/local/tmp/frida-server
  adb shell su -c "chmod 755 /data/local/tmp/frida-server"
  adb shell su -c "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
  adb forward tcp:27042 tcp:27042
  ```

### 2. 安装靶场 APK

```bash
adb install -r apks/frida-target.apk
```

也可以自行编译（需配置 JDK 17 与 Android NDK）：

```bash
./gradlew assembleDebug
```

### 3. 运行各场景脚本

```bash
# 场景一：Java 层 Hook 与 XOR 字符串还原（冷启动 Spawn）
frida -U -f com.demo.reajiagu -l scripts/01_hook_java.js

# 场景二：Java + Native 混合调用栈追踪
frida -U -f com.demo.reajiagu -l scripts/02_backtrace.js

# 场景三：Native 导出符号枚举、.rodata 内存扫描与底层算子 Hook
frida -U -f com.demo.reajiagu -l scripts/03_native_memscan.js

# 场景四：篡改 Native 校验返回值绕过激活码验证
frida -U -f com.demo.reajiagu -l scripts/04_bypass_license.js

# 场景五：通过 Python RPC 直接调用进程内 Native 算子（需先打开 App）
python scripts/05_rpc_client.py

# 全链路一键自动化验证（自动截图保存到 screenshots/）
python scripts/frida_full_suite.py
```
