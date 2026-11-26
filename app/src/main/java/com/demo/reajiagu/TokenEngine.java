package com.demo.reajiagu;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class TokenEngine {
    private static final String APP_CHANNEL = "shield_cloudgame_demo";
    private static final int XOR_MAGIC = 0x5A;

    private TokenEngine() {}

    /**
     * 核心业务算法 1：生成启动鉴权 Token（Java 层字符串混淆 + SHA-256 摘要 + Native 签名拼接）
     */
    public static String generateBootToken(String pkgName, long seed) {
        String rawHeader = deobfuscatePrefix() + ":" + pkgName + ":" + APP_CHANNEL + ":" + seed;
        String shaPart = sha256Short(rawHeader);
        String nativePart = NativeBridge.signPayloadNative(rawHeader, seed);
        return " V1_" + shaPart + "_" + nativePart;
    }

    /**
     * 核心业务算法 2：校验 VIP 激活码并返回解锁等级
     */
    public static int verifyVipOrder(String userId, String licenseCode, int amountCent) {
        if (userId == null || userId.isEmpty() || amountCent <= 0) {
            return -1;
        }
        boolean nativeOk = NativeBridge.verifyLicenseCodeNative(licenseCode);
        if (!nativeOk) {
            return 0;
        }
        int score = (userId.hashCode() & 0x7FFF) + (amountCent / 100) * 17;
        return (score % 2 == 0) ? 2 : 1;
    }

    private static String deobfuscatePrefix() {
        // 异或还原 "CG_AUTH"
        byte[] enc = new byte[]{0x19, 0x1D, 0x05, 0x1B, 0x0F, 0x0E, 0x12};
        byte[] out = new byte[enc.length];
        for (int i = 0; i < enc.length; i++) {
            out[i] = (byte) (enc[i] ^ XOR_MAGIC);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static String sha256Short(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8 && i < digest.length; i++) {
                sb.append(String.format("%02x", digest[i] & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return "0000000000000000";
        }
    }
}
