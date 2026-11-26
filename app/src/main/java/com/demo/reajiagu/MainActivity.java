package com.demo.reajiagu;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 64, 48, 48);
        root.setBackgroundColor(Color.parseColor("#0F172A"));

        TextView title = new TextView(this);
        title.setText("Frida × AI Agent 动态插桩逆向靶场");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(20f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView subTitle = new TextView(this);
        subTitle.setText("Package: " + getPackageName() + "  |  Application: " + getApplication().getClass().getName());
        subTitle.setTextColor(Color.parseColor("#94A3B8"));
        subTitle.setTextSize(12f);
        subTitle.setPadding(0, 12, 0, 32);
        root.addView(subTitle);

        final TextView resultBox = new TextView(this);
        resultBox.setBackgroundColor(Color.parseColor("#1E293B"));
        resultBox.setTextColor(Color.parseColor("#38BDF8"));
        resultBox.setTypeface(Typeface.MONOSPACE);
        resultBox.setTextSize(13f);
        resultBox.setPadding(32, 32, 32, 32);

        String bootToken = DemoApplication.getBootToken();
        int vipLevel = TokenEngine.verifyVipOrder("player_10086", "REA-2026-PRO", 6800);
        resultBox.setText(
                "[Boot Token]\n" + bootToken.trim() + "\n\n" +
                "[Default License Verify]\n" +
                "Input : userId=player_10086, code=REA-2026-PRO, amount=6800\n" +
                "Result: VIP_LEVEL=" + vipLevel
        );
        root.addView(resultBox);

        final EditText licenseInput = new EditText(this);
        licenseInput.setHint("输入激活码测试 (例如 REA-2026-PRO)");
        licenseInput.setText("REA-2026-PRO");
        licenseInput.setTextColor(Color.WHITE);
        licenseInput.setHintTextColor(Color.parseColor("#64748B"));
        root.addView(licenseInput);

        Button verifyBtn = new Button(this);
        verifyBtn.setText("执行 TokenEngine.verifyVipOrder 校验");
        verifyBtn.setGravity(Gravity.CENTER);
        verifyBtn.setOnClickListener(v -> {
            String code = licenseInput.getText().toString().trim();
            long ts = System.currentTimeMillis() / 1000L;
            String dynamicToken = TokenEngine.generateBootToken(getPackageName(), ts);
            int level = TokenEngine.verifyVipOrder("player_10086", code, 12800);
            resultBox.setText(
                    "[Dynamic Token @ " + ts + "]\n" + dynamicToken.trim() + "\n\n" +
                    "[License Check]\n" +
                    "Code  : " + code + "\n" +
                    "Level : " + level + (level > 0 ? " (VALID ✅)" : " (REJECTED ❌)")
            );
        });
        root.addView(verifyBtn);

        setContentView(root);
    }
}
