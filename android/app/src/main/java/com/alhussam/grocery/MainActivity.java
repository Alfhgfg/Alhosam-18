package com.alhussam.grocery;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Base64;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

import com.getcapacitor.BridgeActivity;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginHandle;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

import ee.forgr.capacitor.social.login.GoogleProvider;
import ee.forgr.capacitor.social.login.ModifiedMainActivityForSocialLoginPlugin;
import ee.forgr.capacitor.social.login.SocialLoginPlugin;

public class MainActivity extends BridgeActivity implements ModifiedMainActivityForSocialLoginPlugin {

    private static final String AUTH_LOG_TAG = "AlHussamAuth";
    private static final String EXPECTED_WEB_CLIENT_ID =
        "721494882410-v77p8bf1j61p7gcs9oraaj68iq44prc7.apps.googleusercontent.com";

    private boolean webViewBridgeAttached = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureWebView();
    }

    @Override
    public void onStart() {
        super.onStart();
        configureWebView();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode >= GoogleProvider.REQUEST_AUTHORIZE_GOOGLE_MIN && requestCode < GoogleProvider.REQUEST_AUTHORIZE_GOOGLE_MAX) {
            Log.i(AUTH_LOG_TAG, "onActivityResult Google auth requestCode=" + requestCode + " resultCode=" + resultCode);
            if (getBridge() == null) {
                Log.w(AUTH_LOG_TAG, "onActivityResult skipped: Capacitor bridge is null");
                return;
            }
            PluginHandle pluginHandle = getBridge().getPlugin("SocialLogin");
            if (pluginHandle == null) {
                Log.w(AUTH_LOG_TAG, "onActivityResult skipped: SocialLogin pluginHandle is null");
                return;
            }
            Plugin plugin = pluginHandle.getInstance();
            if (!(plugin instanceof SocialLoginPlugin)) {
                Log.w(AUTH_LOG_TAG, "onActivityResult skipped: plugin is not SocialLoginPlugin");
                return;
            }
            ((SocialLoginPlugin) plugin).handleGoogleLoginIntent(requestCode, data);
        }
    }

    @Override
    public void IHaveModifiedTheMainActivityForTheUseWithSocialLoginPlugin() {}

    private void configureWebView() {
        if (this.bridge == null || this.bridge.getWebView() == null) {
            return;
        }
        WebView webView = this.bridge.getWebView();
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setMediaPlaybackRequiresUserGesture(false);

        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        cookieManager.setAcceptThirdPartyCookies(webView, true);

        if (!webViewBridgeAttached) {
            webView.addJavascriptInterface(new AndroidFileBridge(), "AndroidFileBridge");
            webViewBridgeAttached = true;
        }
    }

    private String computeCertFingerprint(Signature signature, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(signature.toByteArray());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private Signature getPrimarySigningSignature() {
        try {
            PackageManager pm = getPackageManager();
            String pkg = getPackageName();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                if (info.signingInfo != null) {
                    Signature[] signers = info.signingInfo.hasMultipleSigners()
                        ? info.signingInfo.getApkContentsSigners()
                        : info.signingInfo.getSigningCertificateHistory();
                    if (signers != null && signers.length > 0) {
                        return signers[0];
                    }
                }
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                @SuppressWarnings("deprecation")
                Signature[] signers = info.signatures;
                if (signers != null && signers.length > 0) {
                    return signers[0];
                }
            }
        } catch (Exception e) {
            Log.w(AUTH_LOG_TAG, "Unable to inspect APK signing certificate", e);
        }
        return null;
    }

    private String launchModeLabel(int mode) {
        switch (mode) {
            case ActivityInfo.LAUNCH_MULTIPLE:
                return "standard";
            case ActivityInfo.LAUNCH_SINGLE_TOP:
                return "singleTop";
            case ActivityInfo.LAUNCH_SINGLE_TASK:
                return "singleTask";
            case ActivityInfo.LAUNCH_SINGLE_INSTANCE:
                return "singleInstance";
            default:
                return "mode_" + mode;
        }
    }

    private class AndroidFileBridge {
        @JavascriptInterface
        public String getGoogleAuthRuntimeDiagnostics() {
            JSONObject obj = new JSONObject();
            try {
                PackageManager pm = getPackageManager();
                String pkg = getPackageName();
                obj.put("packageName", pkg);

                PackageInfo appInfo = pm.getPackageInfo(pkg, 0);
                obj.put("versionName", appInfo.versionName != null ? appInfo.versionName : "unknown");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    obj.put("versionCode", appInfo.getLongVersionCode());
                } else {
                    @SuppressWarnings("deprecation")
                    int vCode = appInfo.versionCode;
                    obj.put("versionCode", vCode);
                }

                Signature sig = getPrimarySigningSignature();
                obj.put("signingSha1", sig != null ? computeCertFingerprint(sig, "SHA-1") : JSONObject.NULL);
                obj.put("signingSha256", sig != null ? computeCertFingerprint(sig, "SHA-256") : JSONObject.NULL);

                try {
                    PackageInfo gmsInfo = pm.getPackageInfo("com.google.android.gms", 0);
                    obj.put("playServicesInstalled", true);
                    obj.put("playServicesVersion", gmsInfo.versionName != null ? gmsInfo.versionName : "installed");
                } catch (Exception gmsErr) {
                    obj.put("playServicesInstalled", false);
                    obj.put("playServicesVersion", JSONObject.NULL);
                }

                int webClientIdResId = getResources().getIdentifier("default_web_client_id", "string", pkg);
                boolean hasWebClientRes = webClientIdResId != 0;
                obj.put("hasDefaultWebClientIdRes", hasWebClientRes);
                if (hasWebClientRes) {
                    String resWebClientId = getResources().getString(webClientIdResId);
                    obj.put("defaultWebClientIdMatches", EXPECTED_WEB_CLIENT_ID.equals(resWebClientId));
                    int len = resWebClientId.length();
                    obj.put(
                        "defaultWebClientIdSuffix",
                        len > 24 ? "..." + resWebClientId.substring(len - 24) : resWebClientId
                    );
                } else {
                    obj.put("defaultWebClientIdMatches", false);
                    obj.put("defaultWebClientIdSuffix", JSONObject.NULL);
                }

                int googleAppIdResId = getResources().getIdentifier("google_app_id", "string", pkg);
                obj.put("hasGoogleAppIdRes", googleAppIdResId != 0);

                try {
                    ActivityInfo actInfo = pm.getActivityInfo(getComponentName(), 0);
                    obj.put("launchMode", launchModeLabel(actInfo.launchMode));
                } catch (Exception actErr) {
                    obj.put("launchMode", JSONObject.NULL);
                }

                boolean pluginLoaded = getBridge() != null && getBridge().getPlugin("SocialLogin") != null;
                obj.put("socialLoginPluginLoaded", pluginLoaded);
                obj.put("implementsModifiedMainActivity", true);
            } catch (Exception e) {
                try {
                    obj.put("error", e.getMessage());
                } catch (Exception ignored) {}
            }
            return obj.toString();
        }

        @JavascriptInterface
        public boolean saveFile(String base64Data, String fileName, String mimeType) {
            try {
                byte[] bytes = Base64.decode(base64Data, Base64.DEFAULT);
                String safeName = fileName.replaceAll("[\\\\/:*?\"<>|]", "_");

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ContentValues values = new ContentValues();
                    values.put(MediaStore.Downloads.DISPLAY_NAME, safeName);
                    values.put(MediaStore.Downloads.MIME_TYPE, mimeType);
                    values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/AlHussam");

                    ContentResolver resolver = getContentResolver();
                    Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                    if (uri == null) return false;
                    try (OutputStream out = resolver.openOutputStream(uri)) {
                        if (out == null) return false;
                        out.write(bytes);
                        out.flush();
                    }
                } else {
                    File downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                    File appDir = new File(downloadsDir, "AlHussam");
                    if (!appDir.exists()) {
                        appDir.mkdirs();
                    }
                    File outFile = new File(appDir, safeName);
                    try (FileOutputStream fos = new FileOutputStream(outFile)) {
                        fos.write(bytes);
                        fos.flush();
                    }
                }

                runOnUiThread(() ->
                    Toast.makeText(
                        MainActivity.this,
                        "تم حفظ الملف في مجلد التنزيلات (Downloads/AlHussam): " + safeName,
                        Toast.LENGTH_LONG
                    ).show()
                );
                return true;
            } catch (Exception e) {
                runOnUiThread(() ->
                    Toast.makeText(
                        MainActivity.this,
                        "تعذر حفظ الملف: " + e.getMessage(),
                        Toast.LENGTH_LONG
                    ).show()
                );
                return false;
            }
        }
    }
}
