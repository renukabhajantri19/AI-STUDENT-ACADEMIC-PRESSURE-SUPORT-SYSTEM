package edu.clarity.support;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.content.Context;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final int PICK_FILE = 71;
    private static final String PREFS = "clarity_settings";
    private WebView webView;
    private LinearLayout root;
    private ValueCallback<Uri[]> fileCallback;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        String saved = getSharedPreferences(PREFS, MODE_PRIVATE).getString("server", "");
        if (saved.isEmpty()) showServerEntry(""); else showSite(saved, false);
    }

    private void showServerEntry(String initial) {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(48), dp(24), dp(24));
        root.setBackgroundColor(0xfff7f8fc);

        TextView title = new TextView(this);
        title.setText("Connect to your Clarity server");
        title.setTextSize(24);
        title.setTextColor(0xff18233b);
        root.addView(title);

        TextView help = new TextView(this);
        help.setText("On the computer running Clarity, find its Wi-Fi IPv4 address, then enter it with port 8000. Example: http://192.168.1.25:8000");
        help.setTextSize(16);
        help.setTextColor(0xff4c5a70);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(-1, -2);
        hp.topMargin = dp(14);
        root.addView(help, hp);

        EditText address = new EditText(this);
        address.setSingleLine(true);
        address.setInputType( Uri.parse("http://").isHierarchical() ? 17 : 1 );
        address.setHint("http://192.168.1.25:8000");
        address.setText(initial);
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(-1, -2);
        ep.topMargin = dp(24);
        root.addView(address, ep);

        Button connect = new Button(this);
        connect.setText("Connect");
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, -2);
        bp.topMargin = dp(16);
        root.addView(connect, bp);
        connect.setOnClickListener(v -> {
            String value = address.getText().toString().trim().replaceAll("/+$", "");
            if (!value.matches("(?i)^http://[^\\s/]+(?::[0-9]{1,5})?$")) {
                address.setError("Enter an address like http://192.168.1.25:8000");
                return;
            }
            getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString("server", value).apply();
            ((InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(address.getWindowToken(), 0);
            showSite(value, false);
        });
        setContentView(root);
    }

    private void showSite(String baseUrl, boolean reload) {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        ProgressBar progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        root.addView(progress, new LinearLayout.LayoutParams(-1, dp(3)));
        webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setAllowFileAccess(false);
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri.getHost() != null && !uri.getHost().equals(Uri.parse(baseUrl).getHost())) {
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    return true;
                }
                return false;
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override public void onProgressChanged(WebView view, int value) { progress.setProgress(value); progress.setVisibility(value >= 100 ? View.GONE : View.VISIBLE); }
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                Intent pick = new Intent(Intent.ACTION_GET_CONTENT);
                pick.addCategory(Intent.CATEGORY_OPENABLE);
                pick.setType("*/*");
                startActivityForResult(Intent.createChooser(pick, "Choose attachment"), PICK_FILE);
                return true;
            }
        });
        root.addView(webView, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
        if (!reload) webView.loadUrl(baseUrl);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_FILE && fileCallback != null) {
            fileCallback.onReceiveValue(resultCode == RESULT_OK && data != null ? new Uri[]{data.getData()} : null);
            fileCallback = null;
        }
    }

    @Override public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack();
        else if (webView != null) showServerEntry(getSharedPreferences(PREFS, MODE_PRIVATE).getString("server", ""));
        else super.onBackPressed();
    }

    private int dp(int value) { return (int)(value * getResources().getDisplayMetrics().density + 0.5f); }
}
