#!/usr/bin/env python3
"""
Google Play Console Graphical Asset Generator for NetPulse v4.5.0.
Generates exact-resolution 24-bit/32-bit opaque PNG assets required by Google Play Store:
  - icon_512x512.png (512x512 App Icon)
  - feature_graphic_1024x500.png (1024x500 Feature Graphic)
  - phone_screenshot_1_decloaker_1080x1920.png (1080x1920 Phone Screenshot 1)
  - phone_screenshot_2_geiger_1080x1920.png (1080x1920 Phone Screenshot 2)
  - phone_screenshot_3_lan_control_1080x1920.png (1080x1920 Phone Screenshot 3)
  - phone_screenshot_4_topology_1080x1920.png (1080x1920 Phone Screenshot 4)
  - tablet_screenshot_1_workbench_1920x1080.png (1920x1080 Tablet/Desktop Screenshot)
"""

import pathlib
import math
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT_DIR = Path(str(pathlib.Path(__file__).resolve().parents[1] / "play_store_assets"))

BG_DARK = (5, 8, 17)
BG_PANEL = (11, 18, 34)
BG_CARD = (16, 26, 48)
TINT_CYAN = (10, 44, 62)
TINT_EMERALD = (10, 46, 38)
TINT_PURPLE = (36, 20, 62)
CYAN = (0, 240, 255)
CYAN_DIM = (0, 140, 170)
EMERALD = (16, 185, 129)
PURPLE = (168, 85, 247)
AMBER = (245, 158, 11)
ROSE = (244, 63, 94)
TEXT_MAIN = (226, 232, 240)
TEXT_MUTED = (148, 163, 184)
BORDER = (30, 48, 80)


def _font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    candidates = []
    if mono:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ]
    elif bold:
        candidates = [
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
    else:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


def _draw_grid(draw: ImageDraw.ImageDraw, width: int, height: int, step: int = 48) -> None:
    grid_color = (14, 25, 45)
    for x in range(0, width, step):
        draw.line([(x, 0), (x, height)], fill=grid_color, width=1)
    for y in range(0, height, step):
        draw.line([(0, y), (width, y)], fill=grid_color, width=1)


def _draw_radar_graphic(draw: ImageDraw.ImageDraw, cx: int, cy: int, radius: int, compact: bool = False) -> None:
    for frac, col in [(1.0, CYAN_DIM), (0.72, BORDER), (0.45, CYAN_DIM), (0.2, EMERALD)]:
        r = int(radius * frac)
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=col, width=3)
    draw.line([(cx - radius, cy), (cx + radius, cy)], fill=BORDER, width=2)
    draw.line([(cx, cy - radius), (cx, cy + radius)], fill=BORDER, width=2)
    for deg in range(-35, 10, 5):
        rad = math.radians(deg)
        ex = cx + int(radius * math.cos(rad))
        ey = cy + int(radius * math.sin(rad))
        draw.line([(cx, cy), (ex, ey)], fill=(0, 95, 120), width=2)

    blips = [
        (0.48, -28, CYAN, "GW .12.1" if compact else "GW 192.168.12.1"),
        (0.66, 42, ROSE, "CLOAKED [96%]" if compact else "CLOAKED BSSID [96%]"),
        (0.42, 135, EMERALD, "PS5 Console"),
        (0.75, -125, AMBER, "ESP32 Cam" if compact else "Espressif IoT Cam"),
        (0.58, 205, PURPLE, "HomeKit HAP"),
    ]
    f_lbl = _font(15 if compact else 18, bold=True, mono=True)
    for dist, deg, col, label in blips:
        rad = math.radians(deg)
        bx = cx + int(radius * dist * math.cos(rad))
        by = cy + int(radius * dist * math.sin(rad))
        draw.ellipse([bx - 9, by - 9, bx + 9, by + 9], fill=col, outline=TEXT_MAIN, width=2)
        draw.text((bx + 13, by - 9), label, fill=col, font=f_lbl)


def generate_icon_512() -> Path:
    img = Image.new("RGB", (512, 512), BG_DARK)
    draw = ImageDraw.Draw(img)
    _draw_grid(draw, 512, 512, step=32)

    draw.rounded_rectangle([16, 16, 496, 496], radius=96, fill=BG_PANEL, outline=CYAN, width=6)
    cx, cy = 256, 256
    for r, col, w in [(190, CYAN_DIM, 4), (140, PURPLE, 3), (92, EMERALD, 3)]:
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=col, width=w)

    draw.line([(66, cy), (446, cy)], fill=BORDER, width=3)
    draw.line([(cx, 66), (cx, 446)], fill=BORDER, width=3)

    pts = [
        (76, 256),
        (155, 256),
        (185, 190),
        (220, 340),
        (256, 120),
        (292, 365),
        (325, 210),
        (355, 256),
        (436, 256),
    ]
    draw.line(pts, fill=CYAN, width=10, joint="curve")

    for bx, by, col in [(160, 150, EMERALD), (362, 164, ROSE), (340, 355, AMBER)]:
        draw.ellipse([bx - 12, by - 12, bx + 12, by + 12], fill=col, outline=TEXT_MAIN, width=3)

    draw.rounded_rectangle([136, 412, 376, 462], radius=16, fill=BG_DARK, outline=CYAN, width=2)
    f_badge = _font(24, bold=True, mono=True)
    draw.text((166, 423), "NETPULSE v4.5", fill=CYAN, font=f_badge)

    out = OUT_DIR / "icon_512x512.png"
    img.save(out, "PNG")
    return out


def generate_feature_graphic_1024x500() -> Path:
    img = Image.new("RGB", (1024, 500), BG_DARK)
    draw = ImageDraw.Draw(img)
    _draw_grid(draw, 1024, 500, step=40)

    draw.rectangle([8, 8, 1016, 492], outline=CYAN_DIM, width=3)

    # Right side radar visualization cleanly contained
    _draw_radar_graphic(draw, 815, 250, 155, compact=True)

    # Left side branding & value props
    draw.rounded_rectangle([38, 36, 365, 76], radius=10, fill=TINT_CYAN, outline=CYAN, width=2)
    draw.text((54, 46), "OMNISIGHT TACTICAL ENGINE v4.5", fill=CYAN, font=_font(16, bold=True, mono=True))

    draw.text((38, 92), "NETPULSE", fill=TEXT_MAIN, font=_font(62, bold=True))
    draw.text((38, 166), "HIDDEN WIFI DE-CLOAKER & LAN GUARDIAN", fill=EMERALD, font=_font(21, bold=True, mono=True))

    bullets = [
        ("8-STAGE DE-CLOAKER", "Uncover hidden SSIDs & BSSID clones"),
        ("RF GEIGER + GAUSS", "dBm sonar + 3-axis magnetic lens finder"),
        ("DEEP PACKET DPI", "Live KB/s, TLS JA3, DNS SNI & p0f OS"),
        ("SMART IOT CONTROL", "Wake PS5, Kasa/Shelly & ARP quarantine"),
    ]
    y = 218
    for tag, desc in bullets:
        draw.rounded_rectangle([38, y, 236, y + 36], radius=8, fill=BG_CARD, outline=CYAN_DIM, width=2)
        draw.text((50, y + 8), tag, fill=CYAN, font=_font(15, bold=True, mono=True))
        draw.text((250, y + 8), desc, fill=TEXT_MAIN, font=_font(16, bold=False))
        y += 48

    draw.rounded_rectangle([38, 426, 540, 468], radius=10, fill=TINT_EMERALD, outline=EMERALD, width=2)
    draw.text((54, 437), "ZERO CLOUD SPYWARE • 100% ON-DEVICE FORENSICS", fill=EMERALD, font=_font(16, bold=True, mono=True))

    out = OUT_DIR / "feature_graphic_1024x500.png"
    img.save(out, "PNG")
    return out


def _phone_frame(title: str, subtitle: str, active_tab: int) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (1080, 1920), BG_DARK)
    draw = ImageDraw.Draw(img)
    _draw_grid(draw, 1080, 1920, step=48)

    draw.rounded_rectangle([40, 40, 1040, 250], radius=24, fill=BG_PANEL, outline=CYAN, width=3)
    draw.text((76, 68), title, fill=CYAN, font=_font(40, bold=True))
    draw.text((76, 132), subtitle, fill=TEXT_MAIN, font=_font(24, bold=False))
    draw.text((76, 184), "NETPULSE v4.5.0 • ANDROID NATIVE + LAN BRIDGE", fill=EMERALD, font=_font(20, bold=True, mono=True))

    draw.rounded_rectangle([40, 280, 1040, 1860], radius=32, fill=(8, 13, 26), outline=BORDER, width=4)
    draw.rounded_rectangle([70, 310, 1010, 390], radius=14, fill=BG_CARD, outline=BORDER, width=2)
    draw.text((96, 334), "NETPULSE // FIELD SCANNER", fill=CYAN, font=_font(24, bold=True, mono=True))
    draw.rounded_rectangle([750, 324, 986, 376], radius=12, fill=TINT_EMERALD, outline=EMERALD, width=2)
    draw.text((776, 337), "PRO GUARDIAN", fill=EMERALD, font=_font(20, bold=True, mono=True))

    tabs = ["DE-CLOAK", "GEIGER", "LAN HOSTS", "RADAR", "ALERTS"]
    tab_w = 940 // len(tabs)
    for idx, tname in enumerate(tabs):
        tx = 70 + idx * tab_w
        is_act = idx == active_tab
        draw.rounded_rectangle(
            [tx + 4, 1745, tx + tab_w - 4, 1830],
            radius=14,
            fill=TINT_CYAN if is_act else BG_CARD,
            outline=CYAN if is_act else BORDER,
            width=3 if is_act else 1,
        )
        draw.text((tx + 24, 1775), tname, fill=CYAN if is_act else TEXT_MUTED, font=_font(20, bold=True, mono=True))

    return img, draw


def generate_phone_screenshot_1_decloaker() -> Path:
    img, draw = _phone_frame(
        "8-STAGE HIDDEN WIFI DE-CLOAKER",
        "Correlate masked BSSIDs, TSF clock drift & rogue IoT radios in real time",
        active_tab=0,
    )
    kpis = [
        ("TOTAL RADIOS", "24", CYAN),
        ("CLOAKED SSID", "4", ROSE),
        ("BSSID SIBLINGS", "3", AMBER),
        ("SPOOF ALERTS", "1", PURPLE),
    ]
    for i, (k, v, col) in enumerate(kpis):
        x0 = 70 + i * 238
        draw.rounded_rectangle([x0, 415, x0 + 226, 545], radius=16, fill=BG_CARD, outline=col, width=2)
        draw.text((x0 + 20, 432), k, fill=TEXT_MUTED, font=_font(18, bold=True, mono=True))
        draw.text((x0 + 20, 470), v, fill=col, font=_font(44, bold=True, mono=True))

    cards = [
        {
            "ssid": "<HIDDEN SSID> -> RESOLVED: 'HomeNet-5G-Backhaul'",
            "bssid": "B4:FB:E4:89:22:1C (Ubiquiti Inc.)",
            "rssi": "-41 dBm • Ch 149 (5745 MHz) • 80 MHz • WPA3-SAE",
            "stage": "STAGE 1+5 (96% CONF): OUI Sibling of B4:FB:E4:89:22:1B + TSF Offset < 4us",
            "col": ROSE,
        },
        {
            "ssid": "<HIDDEN SSID> -> CAMERA AP CLUSTER",
            "bssid": "A8:03:2A:44:19:F0 (Espressif Inc. ESP32-CAM)",
            "rssi": "-48 dBm • Ch 6 (2437 MHz) • 20 MHz • WPA2-PSK",
            "stage": "STAGE 3+4 (89% CONF): High-Risk IoT Camera OUI + 11n HT Capabilities Match",
            "col": AMBER,
        },
        {
            "ssid": "TMO-G4AR-Gateway",
            "bssid": "78:D6:D6:99:C8:3D (Arcadyan Corp.)",
            "rssi": "-36 dBm • Ch 36 (5180 MHz) • 160 MHz • Wi-Fi 6E",
            "stage": "VERIFIED PRIMARY GATEWAY • 802.11k/v/r Fast Roaming • 0 Spoof Anomalies",
            "col": EMERALD,
        },
        {
            "ssid": "<HIDDEN SSID> -> DIRECT-72-HP-LaserJet",
            "bssid": "3E:D9:2B:11:04:8A (Locally Administered MAC)",
            "rssi": "-61 dBm • Ch 11 (2462 MHz) • 20 MHz • WPS Enabled",
            "stage": "STAGE 2+6 (84% CONF): U/L Bit Virtual AP + WPS UUID-E Vendor Decode",
            "col": PURPLE,
        },
    ]
    y = 575
    for c in cards:
        draw.rounded_rectangle([70, y, 1010, y + 265], radius=18, fill=BG_CARD, outline=c["col"], width=3)
        draw.text((96, y + 22), c["ssid"], fill=c["col"], font=_font(24, bold=True))
        draw.text((96, y + 66), c["bssid"], fill=TEXT_MAIN, font=_font(22, bold=True, mono=True))
        draw.text((96, y + 108), c["rssi"], fill=CYAN, font=_font(20, mono=True))
        draw.rounded_rectangle([96, y + 155, 984, y + 240], radius=12, fill=BG_PANEL, outline=BORDER, width=2)
        draw.text((114, y + 185), c["stage"], fill=TEXT_MAIN, font=_font(16, bold=True, mono=True))
        y += 286

    out = OUT_DIR / "phone_screenshot_1_decloaker_1080x1920.png"
    img.save(out, "PNG")
    return out


def generate_phone_screenshot_2_geiger() -> Path:
    img, draw = _phone_frame(
        "RF GEIGER COUNTER & LENS FINDER",
        "Sweep rooms with live dBm proximity sonar & 3-axis uT magnetic sensor",
        active_tab=1,
    )
    draw.rounded_rectangle([70, 415, 1010, 620], radius=20, fill=BG_CARD, outline=ROSE, width=3)
    draw.text((98, 438), "LOCKED TARGET: A8:03:2A:44:19:F0 (Espressif Hidden Radio)", fill=ROSE, font=_font(23, bold=True, mono=True))
    draw.text((98, 488), "-38 dBm", fill=CYAN, font=_font(72, bold=True, mono=True))
    draw.text((440, 500), "EST. RANGE: 0.8 METERS", fill=EMERALD, font=_font(30, bold=True, mono=True))
    draw.text((440, 548), "AUDIO SONAR: 880 Hz (HOT PROXIMITY)", fill=AMBER, font=_font(20, bold=True, mono=True))

    _draw_radar_graphic(draw, 540, 960, 275)

    draw.rounded_rectangle([70, 1285, 1010, 1715], radius=20, fill=BG_CARD, outline=PURPLE, width=3)
    draw.text((98, 1312), "3-AXIS MAGNETOMETER // FERROMAGNETIC COIL DETECTOR", fill=PURPLE, font=_font(23, bold=True, mono=True))
    draw.text((98, 1364), "94.6 uT", fill=ROSE, font=_font(64, bold=True, mono=True))
    draw.text((420, 1382), "DELTA: +46.2 uT ABOVE BASELINE", fill=AMBER, font=_font(24, bold=True, mono=True))
    draw.text((420, 1422), "ALERT: Speaker coil / lens assembly detected", fill=TEXT_MAIN, font=_font(20))

    for i in range(36):
        bx = 100 + i * 24
        h = int(40 + 95 * abs(math.sin(i * 0.35)))
        col = ROSE if h > 105 else (AMBER if h > 75 else CYAN)
        draw.rectangle([bx, 1680 - h, bx + 16, 1680], fill=col)

    out = OUT_DIR / "phone_screenshot_2_geiger_1080x1920.png"
    img.save(out, "PNG")
    return out


def generate_phone_screenshot_3_lan_control() -> Path:
    img, draw = _phone_frame(
        "SMART LAN CONTROL & QUARANTINE",
        "Wake PS5, toggle Kasa/Shelly plugs, view 24h heatmaps & quarantine threats",
        active_tab=2,
    )
    devices = [
        {
            "ip": "192.168.12.238",
            "name": "Sony PlayStation 5 Console (CFI-2000)",
            "vendor": "Sony Interactive Entertainment • Ports: 9295, 987, 9302",
            "bw": "1,420.5 KB/s • JA3: e7d705a3286e19ea • Uptime: 91.7%",
            "actions": ["WAKE PS5 (DDP:987)", "PORT DIFF: 0", "TRUSTED HOST"],
            "col": CYAN,
        },
        {
            "ip": "192.168.12.144",
            "name": "TP-Link Kasa Smart Plug KP115",
            "vendor": "TP-Link Systems Inc. • TCP 9999 XOR Control Ready",
            "bw": "12.4 KB/s • Relay: ON (18.4W Load) • Uptime: 100.0%",
            "actions": ["RELAY ON", "RELAY OFF", "SNMP WALK"],
            "col": EMERALD,
        },
        {
            "ip": "192.168.12.199",
            "name": "UNKNOWN ROGUE HOST (Port 5555 ADB Open)",
            "vendor": "Espressif Inc. • NEW PORT OPENED: TCP/5555, TCP/8554 RTSP",
            "bw": "845.2 KB/s • SNI: stream-relay.external.io • Uptime: 12.5%",
            "actions": ["ARP QUARANTINE ACTIVE", "TCP RST PULSE", "RELEASE"],
            "col": ROSE,
        },
    ]
    y = 420
    for d in devices:
        draw.rounded_rectangle([70, y, 1010, y + 410], radius=20, fill=BG_CARD, outline=d["col"], width=3)
        draw.text((98, y + 24), f"{d['ip']}  //  {d['name']}", fill=d["col"], font=_font(24, bold=True))
        draw.text((98, y + 66), d["vendor"], fill=TEXT_MAIN, font=_font(19, mono=True))
        draw.text((98, y + 104), d["bw"], fill=EMERALD, font=_font(19, bold=True, mono=True))

        draw.text((98, y + 152), "24H PRESENCE TIMELINE (HOURLY AVAILABILITY):", fill=TEXT_MUTED, font=_font(16, bold=True, mono=True))
        for hr in range(24):
            hx = 98 + hr * 36
            active = (hr > 18) if d["col"] == ROSE else (hr % 5 != 0 or d["col"] == EMERALD)
            hcol = d["col"] if active else (25, 38, 64)
            draw.rounded_rectangle([hx, y + 182, hx + 30, y + 226], radius=5, fill=hcol)

        for bi, act in enumerate(d["actions"]):
            bx = 98 + bi * 290
            draw.rounded_rectangle([bx, y + 258, bx + 272, y + 324], radius=12, fill=BG_PANEL, outline=d["col"], width=2)
            draw.text((bx + 18, y + 278), act, fill=d["col"], font=_font(18, bold=True, mono=True))

        draw.text((98, y + 350), "OS FINGERPRINT: Linux 5.15.x (eBPF p0f SYN WSize=65535 TTL=64)", fill=TEXT_MUTED, font=_font(17, mono=True))
        y += 435

    out = OUT_DIR / "phone_screenshot_3_lan_control_1080x1920.png"
    img.save(out, "PNG")
    return out


def generate_phone_screenshot_4_topology() -> Path:
    img, draw = _phone_frame(
        "3-TIER TACTICAL TOPOLOGY RADAR",
        "Visualize Core Gateway, Active LAN Fleet & Ambient 802.11 RF Airspace",
        active_tab=3,
    )
    _draw_radar_graphic(draw, 540, 860, 360)

    draw.rounded_rectangle([70, 1300, 1010, 1715], radius=20, fill=BG_CARD, outline=CYAN, width=3)
    draw.text((98, 1326), "DEEP PACKET TELEMETRY & GUARDIAN SHIELD FEED", fill=CYAN, font=_font(23, bold=True, mono=True))
    events = [
        ("[16:08:12] [HIGH] NEW_DEVICE", "DC:A6:32:8F:11:09 joined 192.168.12.0/24", ROSE),
        ("[16:08:19] [MED]  PORT_OPENED", "192.168.12.199 exposed TCP/5555 (ADB) + TCP/8554", AMBER),
        ("[16:08:24] [INFO] TLS_JA3_DPI", "192.168.12.238 -> playstation.net [JA3 Verified]", CYAN),
        ("[16:08:31] [CRIT] QUARANTINE", "ARP Sinkhole engaged on 192.168.12.199 (0.5s pulse)", EMERALD),
        ("[16:08:40] [INFO] CAST_EUREKA", "Living Room TV (Chromecast Ultra fw 1.56.275994)", PURPLE),
    ]
    ey = 1380
    for ts, msg, col in events:
        draw.text((98, ey), ts, fill=col, font=_font(18, bold=True, mono=True))
        draw.text((430, ey), msg, fill=TEXT_MAIN, font=_font(18, mono=True))
        ey += 62

    out = OUT_DIR / "phone_screenshot_4_topology_1080x1920.png"
    img.save(out, "PNG")
    return out


def generate_tablet_screenshot_1920x1080() -> Path:
    img = Image.new("RGB", (1920, 1080), BG_DARK)
    draw = ImageDraw.Draw(img)
    _draw_grid(draw, 1920, 1080, step=48)

    draw.rounded_rectangle([24, 20, 1896, 104], radius=16, fill=BG_PANEL, outline=CYAN, width=3)
    draw.text((52, 42), "NETPULSE v4.5.0 — ENTERPRISE TACTICAL WORKBENCH", fill=CYAN, font=_font(28, bold=True, mono=True))
    draw.rounded_rectangle([1490, 36, 1868, 88], radius=12, fill=TINT_PURPLE, outline=PURPLE, width=2)
    draw.text((1514, 50), "SOVEREIGN ENTERPRISE TIER", fill=PURPLE, font=_font(20, bold=True, mono=True))

    draw.rounded_rectangle([24, 124, 760, 1056], radius=20, fill=BG_PANEL, outline=BORDER, width=3)
    draw.text((52, 148), "REAL-TIME 3-RING RADAR TOPOLOGY", fill=CYAN, font=_font(22, bold=True, mono=True))
    _draw_radar_graphic(draw, 392, 560, 260)
    draw.text((52, 920), "SUBNET: 192.168.12.0/24 • ACTIVE HOSTS: 18 • RF RADIOS: 24", fill=EMERALD, font=_font(18, bold=True, mono=True))
    draw.text((52, 960), "GUARDIAN SHIELD: ACTIVE (24/7 ARP + PORT DIFF + JA3 DPI)", fill=CYAN, font=_font(18, mono=True))

    draw.rounded_rectangle([784, 124, 1896, 620], radius=20, fill=BG_PANEL, outline=BORDER, width=3)
    draw.text((812, 148), "LIVE LAN FLEET INVENTORY // DPI BANDWIDTH & 24H PRESENCE HEATMAP", fill=CYAN, font=_font(22, bold=True, mono=True))

    rows = [
        ("192.168.12.1", "78:D6:D6:99:C8:3D", "Arcadyan TMO-G4AR Gateway", "420.8 KB/s", "100%", "CORE ROUTER", EMERALD),
        ("192.168.12.238", "BC:33:29:74:A1:10", "Sony PlayStation 5 (CFI-2000)", "1420.5 KB/s", "91.7%", "DDP:987 READY", CYAN),
        ("192.168.12.144", "50:C7:BF:18:44:92", "TP-Link Kasa KP115 Plug", "12.4 KB/s", "100%", "RELAY: ON", EMERALD),
        ("192.168.12.182", "F0:EF:86:22:09:B1", "Google Chromecast Ultra", "610.2 KB/s", "95.8%", "EUREKA:8008", PURPLE),
        ("192.168.12.199", "A8:03:2A:44:19:F0", "Espressif ESP32 RTSP Cam", "845.2 KB/s", "12.5%", "QUARANTINED", ROSE),
    ]
    ry = 210
    for ip, mac, name, bw, up, status, col in rows:
        draw.rounded_rectangle([812, ry, 1868, ry + 70], radius=12, fill=BG_CARD, outline=col, width=2)
        draw.text((832, ry + 22), ip, fill=CYAN, font=_font(19, bold=True, mono=True))
        draw.text((1015, ry + 22), name, fill=TEXT_MAIN, font=_font(19, bold=True))
        draw.text((1410, ry + 22), bw, fill=EMERALD, font=_font(19, bold=True, mono=True))
        draw.text((1575, ry + 22), up, fill=TEXT_MAIN, font=_font(19, mono=True))
        draw.text((1675, ry + 22), status, fill=col, font=_font(18, bold=True, mono=True))
        ry += 80

    draw.rounded_rectangle([784, 644, 1896, 1056], radius=20, fill=BG_PANEL, outline=CYAN_DIM, width=3)
    draw.text((812, 668), "8-STAGE HIDDEN WIFI DE-CLOAKER & GUARDIAN SECURITY TIMELINE", fill=AMBER, font=_font(22, bold=True, mono=True))

    logs = [
        ("STAGE 1+5 DE-CLOAK", "Hidden BSSID B4:FB:E4:89:22:1C resolved to 'HomeNet-5G-Backhaul' (96% conf)", ROSE),
        ("STAGE 3 IOT CAMERA", "Hidden BSSID A8:03:2A:44:19:F0 matched Espressif ESP32-CAM signature (-48 dBm)", AMBER),
        ("GUARDIAN PORT_OPENED", "Host 192.168.12.199 opened TCP/5555 (ADB) + TCP/8554 (RTSP Stream)", ROSE),
        ("HOMEKIT HAP DISCOVERY", "Apple TV 4K Bridge (md=AppleTV14,1 c#=4 s#=1 sf=0) verified on 192.168.12.88", PURPLE),
        ("SNMPv2c SYS_DESCR", "Ubiquiti UniFi Switch USW-24-PoE v6.6.61 uptime 48d 12h 04m", EMERALD),
    ]
    ly = 725
    for tag, detail, col in logs:
        draw.rounded_rectangle([812, ly, 1868, ly + 54], radius=10, fill=BG_CARD, outline=BORDER, width=1)
        draw.text((830, ly + 15), tag, fill=col, font=_font(18, bold=True, mono=True))
        draw.text((1115, ly + 15), detail, fill=TEXT_MAIN, font=_font(17, mono=True))
        ly += 62

    out = OUT_DIR / "tablet_screenshot_1_workbench_1920x1080.png"
    img.save(out, "PNG")
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    generated = [
        generate_icon_512(),
        generate_feature_graphic_1024x500(),
        generate_phone_screenshot_1_decloaker(),
        generate_phone_screenshot_2_geiger(),
        generate_phone_screenshot_3_lan_control(),
        generate_phone_screenshot_4_topology(),
        generate_tablet_screenshot_1920x1080(),
    ]
    for p in generated:
        with Image.open(p) as im:
            print(f"Generated {p.name}: {im.size[0]}x{im.size[1]} {im.mode} ({p.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
