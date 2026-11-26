package com.demo.reajiagu;

import android.app.Application;
import android.util.Log;

public class DemoApplication extends Application {
    private static final String TAG = "ReaJiaguDemo";
    private static String sBootToken = "UNINITIALIZED";

    @Override
    public void onCreate() {
        super.onCreate();
        sBootToken = TokenEngine.generateBootToken(getPackageName(), 20261026L);
        Log.i(TAG, "DemoApplication initialized, bootToken=" + sBootToken);
    }

    public static String getBootToken() {
        return sBootToken;
    }
}
