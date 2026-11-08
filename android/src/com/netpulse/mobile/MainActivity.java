package com.netpulse.mobile;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.net.DhcpInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@SuppressWarnings("deprecation")
public class MainActivity extends Activity implements SensorEventListener {

    private WebView webView;
    private WifiManager wifiManager;
    private SensorManager sensorManager;
    private Vibrator vibrator;

    private final float[] magValues = new float[3];
    private final float[] accelValues = new float[3];
    private boolean hasMag = false;
    private boolean hasAccel = false;
    private float azimuthDeg = 0f;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(Color.parseColor("#090D14"));
        window.setNavigationBarColor(Color.parseColor("#090D14"));

        wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        sensorManager = (SensorManager) getSystemService(Context.SENSOR_SERVICE);
        if (Build.VERSION.SDK_INT >= 31) {
            VibratorManager vm = (VibratorManager) getSystemService(Context.VIBRATOR_MANAGER_SERVICE);
            if (vm != null) {
                vibrator = vm.getDefaultVibrator();
            }
        } else {
            vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        }

        requestRuntimePermissions();

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#090D14"));
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        settings.setMediaPlaybackRequiresUserGesture(false);

        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient());
        webView.addJavascriptInterface(new AndroidNativeBridge(), "AndroidNative");

        setContentView(webView);
        webView.loadUrl("file:///android_asset/mobile.html");
    }

    private void requestRuntimePermissions() {
        List<String> perms = new ArrayList<>();
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        if (checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            perms.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        }
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission("android.permission.NEARBY_WIFI_DEVICES") != PackageManager.PERMISSION_GRANTED) {
                perms.add("android.permission.NEARBY_WIFI_DEVICES");
            }
        }
        if (!perms.isEmpty()) {
            requestPermissions(perms.toArray(new String[0]), 1001);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (sensorManager != null) {
            Sensor mag = sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD);
            Sensor acc = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
            if (mag != null) {
                sensorManager.registerListener(this, mag, SensorManager.SENSOR_DELAY_UI);
            }
            if (acc != null) {
                sensorManager.registerListener(this, acc, SensorManager.SENSOR_DELAY_UI);
            }
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (sensorManager != null) {
            sensorManager.unregisterListener(this);
        }
    }

    @Override
    public void onSensorChanged(SensorEvent event) {
        if (event.sensor.getType() == Sensor.TYPE_MAGNETIC_FIELD) {
            System.arraycopy(event.values, 0, magValues, 0, 3);
            hasMag = true;
        } else if (event.sensor.getType() == Sensor.TYPE_ACCELEROMETER) {
            System.arraycopy(event.values, 0, accelValues, 0, 3);
            hasAccel = true;
        }
        if (hasMag && hasAccel) {
            float[] R = new float[9];
            float[] I = new float[9];
            if (SensorManager.getRotationMatrix(R, I, accelValues, magValues)) {
                float[] orientation = new float[3];
                SensorManager.getOrientation(R, orientation);
                float deg = (float) Math.toDegrees(orientation[0]);
                azimuthDeg = (deg + 360f) % 360f;
            }
        }
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {}

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private static int freqToChannel(int freq) {
        if (freq == 2484) return 14;
        if (freq >= 2412 && freq <= 2472) return (freq - 2407) / 5;
        if (freq >= 5170 && freq <= 5885) return (freq - 5000) / 5;
        if (freq >= 5955 && freq <= 7115) return (freq - 5950) / 5;
        return 0;
    }

    private static String intToIp(int ipInt) {
        return (ipInt & 0xFF) + "." +
               ((ipInt >> 8) & 0xFF) + "." +
               ((ipInt >> 16) & 0xFF) + "." +
               ((ipInt >> 24) & 0xFF);
    }

    private String detectLocalIpv4() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface nif = ifaces.nextElement();
                if (!nif.isUp() || nif.isLoopback()) continue;
                Enumeration<InetAddress> addrs = nif.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "0.0.0.0";
    }

    public class AndroidNativeBridge {

        @JavascriptInterface
        public boolean isNativeApp() {
            return true;
        }

        @JavascriptInterface
        public String getPhoneNetworkInfo() {
            try {
                JSONObject obj = new JSONObject();
                String ip = detectLocalIpv4();
                obj.put("ip", ip);
                obj.put("model", Build.MANUFACTURER + " " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ")");
                if (wifiManager != null) {
                    WifiInfo info = wifiManager.getConnectionInfo();
                    DhcpInfo dhcp = wifiManager.getDhcpInfo();
                    if (info != null) {
                        String ssid = info.getSSID();
                        if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) {
                            ssid = ssid.substring(1, ssid.length() - 1);
                        }
                        obj.put("ssid", ssid != null ? ssid : "");
                        obj.put("bssid", info.getBSSID() != null ? info.getBSSID().toUpperCase() : "");
                        obj.put("rssi_dbm", info.getRssi());
                        obj.put("link_speed_mbps", info.getLinkSpeed());
                        obj.put("freq_mhz", info.getFrequency());
                    }
                    if (dhcp != null && dhcp.gateway != 0) {
                        obj.put("gateway", intToIp(dhcp.gateway));
                    }
                }
                return obj.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public String scanNativeWifi(boolean triggerActive) {
            try {
                if (wifiManager == null) return "[]";
                if (triggerActive) {
                    try { wifiManager.startScan(); } catch (Exception ignored) {}
                }
                List<ScanResult> results = wifiManager.getScanResults();
                JSONArray arr = new JSONArray();
                if (results != null) {
                    for (ScanResult sr : results) {
                        JSONObject ap = new JSONObject();
                        String bssid = sr.BSSID != null ? sr.BSSID.toUpperCase() : "";
                        String ssid = sr.SSID != null ? sr.SSID : "";
                        boolean hidden = ssid.trim().isEmpty();
                        int freq = sr.frequency;
                        int ch = freqToChannel(freq);
                        String band = freq >= 5955 ? "6 GHz" : (freq >= 5000 ? "5 GHz" : "2.4 GHz");
                        long tsfUs = sr.timestamp;
                        long sec = tsfUs / 1000000L;
                        long days = sec / 86400L;
                        long hrs = (sec % 86400L) / 3600L;
                        long mins = (sec % 3600L) / 60L;

                        ap.put("bssid", bssid);
                        ap.put("ssid", hidden ? "[Hidden BSSID]" : ssid);
                        ap.put("is_hidden", hidden);
                        ap.put("signal_dbm", sr.level);
                        ap.put("signal_pct", Math.max(2, Math.min(100, (sr.level + 100) * 2)));
                        ap.put("freq_mhz", freq);
                        ap.put("channel", ch);
                        ap.put("band", band);
                        ap.put("security", sr.capabilities != null ? sr.capabilities : "OPEN");
                        int bwMhz = 20;
                        if (sr.channelWidth == ScanResult.CHANNEL_WIDTH_40MHZ) bwMhz = 40;
                        else if (sr.channelWidth == ScanResult.CHANNEL_WIDTH_80MHZ || sr.channelWidth == ScanResult.CHANNEL_WIDTH_80MHZ_PLUS_MHZ) bwMhz = 80;
                        else if (sr.channelWidth == ScanResult.CHANNEL_WIDTH_160MHZ) bwMhz = 160;
                        ap.put("channel_width_mhz", bwMhz);
                        if (Build.VERSION.SDK_INT >= 30) {
                            int std = sr.getWifiStandard();
                            String stdStr = "802.11";
                            if (std == 8) stdStr = "Wi-Fi 7 (802.11be)";
                            else if (std == 6) stdStr = "Wi-Fi 6 (802.11ax)";
                            else if (std == 5) stdStr = "Wi-Fi 5 (802.11ac)";
                            else if (std == 4) stdStr = "Wi-Fi 4 (802.11n)";
                            ap.put("wifi_standard", stdStr);
                        }
                        ap.put("tsf_usec", tsfUs);
                        ap.put("tsf_human", days + "d " + hrs + "h " + mins + "m");
                        arr.put(ap);
                    }
                }
                return arr.toString();
            } catch (Exception e) {
                return "[]";
            }
        }

        @JavascriptInterface
        public String getDeviceSensors() {
            try {
                JSONObject obj = new JSONObject();
                float bx = magValues[0];
                float by = magValues[1];
                float bz = magValues[2];
                double total = Math.sqrt(bx * bx + by * by + bz * bz);
                obj.put("bx", bx);
                obj.put("by", by);
                obj.put("bz", bz);
                obj.put("mag_total_ut", total);
                obj.put("azimuth_deg", azimuthDeg);
                return obj.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public void vibrate(int ms) {
            try {
                if (vibrator != null && vibrator.hasVibrator()) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        vibrator.vibrate(VibrationEffect.createOneShot(Math.max(5, ms), VibrationEffect.DEFAULT_AMPLITUDE));
                    } else {
                        vibrator.vibrate(Math.max(5, ms));
                    }
                }
            } catch (Exception ignored) {}
        }

        @JavascriptInterface
        public String scanNativeLanSubnet() {
            try {
                String myIp = detectLocalIpv4();
                int lastDot = myIp.lastIndexOf('.');
                if (lastDot <= 0) return "[]";
                final String prefix = myIp.substring(0, lastDot + 1);
                final int[] commonPorts = new int[]{80, 443, 554, 1400, 3000, 8001, 8008, 8060, 8443, 8765, 9999, 62078, 5555, 22};

                ExecutorService pool = Executors.newFixedThreadPool(48);
                List<Future<JSONObject>> futures = new ArrayList<>();

                for (int i = 1; i <= 254; i++) {
                    final String targetIp = prefix + i;
                    futures.add(pool.submit(new Callable<JSONObject>() {
                        @Override
                        public JSONObject call() {
                            try {
                                long t0 = System.currentTimeMillis();
                                boolean reachable = InetAddress.getByName(targetIp).isReachable(320);
                                JSONArray openPorts = new JSONArray();
                                for (int p : commonPorts) {
                                    try (Socket s = new Socket()) {
                                        s.connect(new InetSocketAddress(targetIp, p), 140);
                                        openPorts.put(p);
                                        reachable = true;
                                    } catch (Exception ignored) {}
                                }
                                if (reachable) {
                                    long rtt = System.currentTimeMillis() - t0;
                                    JSONObject host = new JSONObject();
                                    host.put("ip", targetIp);
                                    host.put("rtt_ms", rtt);
                                    host.put("open_ports", openPorts);
                                    return host;
                                }
                            } catch (Exception ignored) {}
                            return null;
                        }
                    }));
                }

                pool.shutdown();
                pool.awaitTermination(8, TimeUnit.SECONDS);

                JSONArray found = new JSONArray();
                for (Future<JSONObject> f : futures) {
                    if (f.isDone()) {
                        try {
                            JSONObject h = f.get();
                            if (h != null) found.put(h);
                        } catch (Exception ignored) {}
                    }
                }
                return found.toString();
            } catch (Exception e) {
                return "[]";
            }
        }

        @JavascriptInterface
        public boolean sendWakeOnLan(final String macStr) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String clean = macStr.replaceAll("[^0-9A-Fa-f]", "");
                        if (clean.length() != 12) return;
                        byte[] macBytes = new byte[6];
                        for (int i = 0; i < 6; i++) {
                            macBytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
                        }
                        byte[] packet = new byte[102];
                        for (int i = 0; i < 6; i++) packet[i] = (byte) 0xFF;
                        for (int i = 1; i <= 16; i++) {
                            System.arraycopy(macBytes, 0, packet, i * 6, 6);
                        }
                        try (DatagramSocket socket = new DatagramSocket()) {
                            socket.setBroadcast(true);
                            DatagramPacket dp = new DatagramPacket(packet, packet.length, InetAddress.getByName("255.255.255.255"), 9);
                            socket.send(dp);
                        }
                    } catch (Exception ignored) {}
                }
            }).start();
            return true;
        }

        @JavascriptInterface
        public void sendRokuKey(final String ip, final String key) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        URL url = URI.create("http://" + ip + ":8060/keypress/" + key).toURL();
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("POST");
                        conn.setConnectTimeout(1200);
                        conn.setReadTimeout(1200);
                        conn.setDoOutput(true);
                        conn.getOutputStream().write(new byte[0]);
                        conn.getResponseCode();
                        conn.disconnect();
                    } catch (Exception ignored) {}
                }
            }).start();
        }

        @JavascriptInterface
        public boolean wakePlayStationNative(final String ip) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String payload = "WAKEUP * HTTP/1.1\nclient-type:vr\nauth-type:C\nmodel:w\napp-type:r\n\n";
                        byte[] data = payload.getBytes("UTF-8");
                        try (DatagramSocket ds = new DatagramSocket()) {
                            for (int port : new int[]{987, 9302}) {
                                DatagramPacket pkt = new DatagramPacket(data, data.length, InetAddress.getByName(ip), port);
                                ds.send(pkt);
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }).start();
            return true;
        }

        @JavascriptInterface
        public boolean controlKasaPlug(final String ip, final int stateVal) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(ip, 9999), 1200);
                        String json = "{\"system\":{\"set_relay_state\":{\"state\":" + stateVal + "}}}";
                        byte[] raw = json.getBytes("UTF-8");
                        byte[] out = new byte[raw.length + 4];
                        int len = raw.length;
                        out[0] = (byte) ((len >> 24) & 0xFF);
                        out[1] = (byte) ((len >> 16) & 0xFF);
                        out[2] = (byte) ((len >> 8) & 0xFF);
                        out[3] = (byte) (len & 0xFF);
                        int key = 171;
                        for (int i = 0; i < raw.length; i++) {
                            int enc = key ^ (raw[i] & 0xFF);
                            key = enc;
                            out[i + 4] = (byte) enc;
                        }
                        s.getOutputStream().write(out);
                        s.getOutputStream().flush();
                    } catch (Exception ignored) {}
                }
            }).start();
            return true;
        }

        @JavascriptInterface
        public void sendTcpResetPulse(final String ip) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    int[] ports = new int[]{80, 443, 8080, 22, 445, 554};
                    for (int p : ports) {
                        try (Socket s = new Socket()) {
                            s.setSoLinger(true, 0);
                            s.connect(new InetSocketAddress(ip, p), 120);
                        } catch (Exception ignored) {}
                    }
                }
            }).start();
        }

        @JavascriptInterface
        public boolean controlSonosNative(final String ip, final String action) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String cleanAct = (action != null && !action.isEmpty()) ? action : "Play";
                        String soap = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
                            "<s:Body><u:" + cleanAct + " xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">" +
                            "<InstanceID>0</InstanceID><Speed>1</Speed>" +
                            "</u:" + cleanAct + "></s:Body></s:Envelope>";
                        byte[] body = soap.getBytes("UTF-8");
                        URL url = URI.create("http://" + ip + ":1400/MediaRenderer/AVTransport/Control").toURL();
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("POST");
                        conn.setConnectTimeout(1400);
                        conn.setReadTimeout(1400);
                        conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"");
                        conn.setRequestProperty("SOAPAction", "\"urn:schemas-upnp-org:service:AVTransport:1#" + cleanAct + "\"");
                        conn.setDoOutput(true);
                        conn.getOutputStream().write(body);
                        conn.getResponseCode();
                        conn.disconnect();
                    } catch (Exception ignored) {}
                }
            }).start();
            return true;
        }

        @JavascriptInterface
        public String scanNativeSsdp() {
            JSONArray out = new JSONArray();
            try (DatagramSocket sock = new DatagramSocket()) {
                sock.setSoTimeout(350);
                String msg = "M-SEARCH * HTTP/1.1\r\n" +
                             "HOST: 239.255.255.250:1900\r\n" +
                             "MAN: \"ssdp:discover\"\r\n" +
                             "MX: 1\r\n" +
                             "ST: ssdp:all\r\n\r\n";
                byte[] bytes = msg.getBytes("UTF-8");
                DatagramPacket pkt = new DatagramPacket(bytes, bytes.length, InetAddress.getByName("239.255.255.250"), 1900);
                sock.send(pkt);
                long deadline = System.currentTimeMillis() + 1100;
                byte[] buf = new byte[2048];
                while (System.currentTimeMillis() < deadline) {
                    try {
                        DatagramPacket rx = new DatagramPacket(buf, buf.length);
                        sock.receive(rx);
                        String resp = new String(rx.getData(), 0, rx.getLength(), "UTF-8");
                        JSONObject item = new JSONObject();
                        item.put("ip", rx.getAddress().getHostAddress());
                        item.put("raw", resp.length() > 240 ? resp.substring(0, 240) : resp);
                        out.put(item);
                    } catch (Exception breakLoop) {
                        break;
                    }
                }
            } catch (Exception ignored) {}
            return out.toString();
        }

        @JavascriptInterface
        public String scanNativeHostPorts(final String ip) {
            final int[] targetPorts = new int[]{
                21, 22, 23, 53, 80, 139, 443, 445, 548, 554, 631, 1400, 1883,
                2375, 3000, 3389, 5000, 5555, 7000, 8001, 8008, 8060, 8080, 8443, 8765, 9999, 11434, 32400
            };
            JSONArray openList = new JSONArray();
            try {
                ExecutorService pool = Executors.newFixedThreadPool(16);
                List<Future<JSONObject>> futs = new ArrayList<>();
                for (final int p : targetPorts) {
                    futs.add(pool.submit(new Callable<JSONObject>() {
                        @Override
                        public JSONObject call() {
                            try (Socket s = new Socket()) {
                                long t0 = System.currentTimeMillis();
                                s.connect(new InetSocketAddress(ip, p), 260);
                                long rtt = System.currentTimeMillis() - t0;
                                s.setSoTimeout(250);
                                String banner = "";
                                try {
                                    if (p == 80 || p == 1400 || p == 8008 || p == 8060 || p == 8080 || p == 11434 || p == 32400) {
                                        s.getOutputStream().write(("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n").getBytes("UTF-8"));
                                        s.getOutputStream().flush();
                                    }
                                    InputStream in = s.getInputStream();
                                    byte[] buf = new byte[160];
                                    int n = in.read(buf);
                                    if (n > 0) {
                                        banner = new String(buf, 0, n, "UTF-8").replace("\r", " ").replace("\n", " ").trim();
                                    }
                                } catch (Exception ignored) {}
                                JSONObject item = new JSONObject();
                                item.put("port", p);
                                item.put("rtt_ms", rtt);
                                item.put("banner", banner);
                                return item;
                            } catch (Exception ignored) {
                                return null;
                            }
                        }
                    }));
                }
                pool.shutdown();
                pool.awaitTermination(5, TimeUnit.SECONDS);
                for (Future<JSONObject> f : futs) {
                    if (f.isDone()) {
                        try {
                            JSONObject o = f.get();
                            if (o != null) openList.put(o);
                        } catch (Exception ignored) {}
                    }
                }
            } catch (Exception ignored) {}
            return openList.toString();
        }
    }
}
