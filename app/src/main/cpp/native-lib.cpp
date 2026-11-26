#include <jni.h>
#include <string>
#include <cstdint>
#include <cstdio>

static const uint8_t kSecretSalt[] = {
    0x52, 0x45, 0x41, 0x5F, 0x4E, 0x41, 0x54, 0x49,
    0x56, 0x45, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x39
}; // "REA_NATIVE_KEY_9"

extern "C" __attribute__((noinline, visibility("default")))
uint32_t computeFnv1a32(const char* data, size_t len) {
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) {
        uint8_t mixed = static_cast<uint8_t>(data[i]) ^ kSecretSalt[i & 0x0F];
        hash ^= mixed;
        hash *= 0x01000193u;
    }
    return hash;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_demo_reajiagu_NativeBridge_signPayloadNative(
        JNIEnv* env,
        jclass /* clazz */,
        jstring payload_jstr,
        jlong timestamp) {
    if (payload_jstr == nullptr) {
        return env->NewStringUTF("ERR_NULL");
    }
    const char* raw = env->GetStringUTFChars(payload_jstr, nullptr);
    std::string combined(raw ? raw : "");
    if (raw != nullptr) {
        env->ReleaseStringUTFChars(payload_jstr, raw);
    }

    char ts_buf[32];
    std::snprintf(ts_buf, sizeof(ts_buf), "|ts=%lld", static_cast<long long>(timestamp));
    combined += ts_buf;

    uint32_t digest = computeFnv1a32(combined.c_str(), combined.size());
    char out_buf[64];
    std::snprintf(out_buf, sizeof(out_buf), "NSIG-%08X-%04X",
                  digest,
                  static_cast<unsigned int>((timestamp ^ 0xA5A5) & 0xFFFF));
    return env->NewStringUTF(out_buf);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_demo_reajiagu_NativeBridge_verifyLicenseCodeNative(
        JNIEnv* env,
        jclass /* clazz */,
        jstring code_jstr) {
    if (code_jstr == nullptr) {
        return JNI_FALSE;
    }
    const char* code = env->GetStringUTFChars(code_jstr, nullptr);
    std::string input(code ? code : "");
    if (code != nullptr) {
        env->ReleaseStringUTFChars(code_jstr, code);
    }
    // 期望格式: "REA-2026-PRO" -> FNV-1a 风格逐字节 XOR 盐混合后的完整哈希为 0xE44C0D32
    if (input.size() != 12) {
        return JNI_FALSE;
    }
    uint32_t h = computeFnv1a32(input.c_str(), input.size());
    return (h == computeFnv1a32("REA-2026-PRO", 12)) ? JNI_TRUE : JNI_FALSE;
}
