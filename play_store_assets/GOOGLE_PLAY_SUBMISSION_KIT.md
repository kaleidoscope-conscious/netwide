# NetPulse // OmniSight v4.5.0 — Google Play Store Submission & Monetization Kit

## 1. Signed App Binary (Ready to Upload)
- **Google Play Android App Bundle (`.aab`)**:
  - Path: `/home/jg/Desktop/NetPulse-Mobile-PlayStore.aab` (also at `/home/jg/netpulse/static/NetPulse-Mobile-PlayStore.aab`)
  - Package Name (`applicationId`): `com.netpulse.mobile`
  - Version Code: `45` (`4.5.0`)
  - Target SDK: `35` (Android 15) / Min SDK: `26` (Android 8.0)
  - Format: Protobuf `aapt2 --proto-format` + `BundleConfig.pb` (`SHA256withRSA` signed)
- **Direct APK (Sideload / Enterprise Distribution)**:
  - Path: `/home/jg/Desktop/NetPulse-Mobile.apk`

---

## 2. Store Listing Copy (Copy & Paste into Play Console)
- **App Name (30 chars max)**:
  `NetPulse: WiFi & LAN Guardian`
- **Short Description (80 chars max)**:
  `8-stage hidden WiFi de-cloaker, RF Geiger counter, DPI radar & smart IoT control`
- **Category**: `Tools` or `Productivity` (Tags: `Network Tools`, `Wi-Fi Analyzer`, `Security`)
- **Privacy Policy URL**: `https://<your-domain>/privacy` (Served natively by NetPulse at `GET /privacy`)

---

## 3. Graphical Assets (`/home/jg/netpulse/play_store_assets/`)
| Asset Type | Resolution | File |
| :--- | :--- | :--- |
| **App Icon** | 512 × 512 (Opaque RGB PNG) | `icon_512x512.png` |
| **Feature Graphic** | 1024 × 500 (Opaque RGB PNG) | `feature_graphic_1024x500.png` |
| **Phone Screenshot 1** | 1080 × 1920 | `phone_screenshot_1_decloaker_1080x1920.png` |
| **Phone Screenshot 2** | 1080 × 1920 | `phone_screenshot_2_geiger_1080x1920.png` |
| **Phone Screenshot 3** | 1080 × 1920 | `phone_screenshot_3_lan_control_1080x1920.png` |
| **Phone Screenshot 4** | 1080 × 1920 | `phone_screenshot_4_topology_1080x1920.png` |
| **10" Tablet / Chromebook** | 1920 × 1080 | `tablet_screenshot_1_workbench_1920x1080.png` |

---

## 4. Google Play Policy & Data Safety Declarations
### A. Data Safety Questionnaire
- **Does your app collect or share any of the required user data types?** → **No**
  - All Wi-Fi BSSID scanning, LAN discovery, and magnetometer sensor readings execute 100% locally on the user's device and local LAN.

### B. Location & Nearby Wi-Fi Devices Permission Declaration
- **Why does your app need `ACCESS_FINE_LOCATION` and `NEARBY_WIFI_DEVICES`?**
  > "NetPulse is a Wi-Fi spectrum analyzer, hidden SSID de-cloaker, and LAN security scanner. Android OS mandates `ACCESS_FINE_LOCATION` and `NEARBY_WIFI_DEVICES` permissions to call `WifiManager.getScanResults()` for inspecting nearby 802.11 BSSIDs, RSSI dBm signal levels, channels, and beacon Information Elements. Physical GPS coordinates are never stored or transmitted off-device."

---

## 5. Monetization & Subscription SKUs
| Tier | Monthly SKU / Price | Annual SKU / Price | Free Trial |
| :--- | :--- | :--- | :--- |
| **Community Free** | `$0` | `$0` | Unlimited |
| **Pro Guardian** | `netpulse_pro_monthly` (`$9.99/mo`) | `netpulse_pro_annual` (`$99.00/yr`) | 7 Days |
| **Sovereign Enterprise** | `netpulse_ent_monthly` (`$29.99/mo`) | `netpulse_ent_annual` (`$299.00/yr`) | — |
