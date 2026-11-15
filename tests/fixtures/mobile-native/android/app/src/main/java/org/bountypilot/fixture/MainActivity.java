package org.bountypilot.fixture;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONObject;

/** Synthetic fixture only. No Internet permission, credentials or outside-app access. */
public final class MainActivity extends Activity {
    private static final String PROTOCOL = "bpilot-mobilefixture-protocol-v1";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        handle(getIntent());
    }
    @Override protected void onNewIntent(Intent incoming) {
        super.onNewIntent(incoming);
        setIntent(incoming);
        handle(incoming);
    }
    private static String declaredDigest() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(PROTOCOL.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
        return hex.toString();
    }
    private void handle(Intent intent) {
        if (intent == null) return;
        Uri uri = intent.getData();
        if (uri == null || !"bpilottest".equals(uri.getScheme())
                || !"probe".equals(uri.getHost())) return;
        String path = uri.getPath();
        String phase = "/candidate".equals(path) ? "candidate"
                : ("/control".equals(path) ? "control" : null);
        String nonce = uri.getQueryParameter("nonce");
        if (phase == null || nonce == null || !nonce.matches("[0-9a-f]{32}")) return;
        try {
            File marker = new File(getFilesDir(), "bpilot-local-marker");
            Files.deleteIfExists(marker.toPath());
            if ("candidate".equals(phase)) {
                try (FileOutputStream out = new FileOutputStream(marker)) {
                    out.write(nonce.getBytes(StandardCharsets.UTF_8));
                }
            }
            boolean seen = marker.isFile()
                    && nonce.equals(new String(Files.readAllBytes(marker.toPath()),
                                               StandardCharsets.UTF_8));
            JSONObject doc = new JSONObject();
            doc.put("schema_version", 1);
            doc.put("phase", phase);
            doc.put("nonce", nonce);
            doc.put("fixture_package", "org.bountypilot.fixture");
            doc.put("fixture_build_sha256", declaredDigest());
            doc.put("sink_seen", seen);
            try (FileOutputStream out = openFileOutput("bpilot-" + phase + ".json", MODE_PRIVATE)) {
                out.write(doc.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
            // Failure means no fresh witness; never invent success.
        }
    }
}
