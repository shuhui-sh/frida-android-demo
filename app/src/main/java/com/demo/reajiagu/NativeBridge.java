package com.demo.reajiagu;

public final class NativeBridge {
    static {
        System.loadLibrary("reajiagu");
    }

    private NativeBridge() {}

    public static native String signPayloadNative(String payload, long timestamp);

    public static native boolean verifyLicenseCodeNative(String licenseCode);
}
