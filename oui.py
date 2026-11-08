"""
Deep IEEE 802 Hardware MAC, Multi-Tier OUI Search & IPv6 EUI-64 / LAA De-Anonymizer Engine.
Loads 47,000–55,000+ entries across:
- /usr/share/ieee-data/oui.csv (24-bit MA-L)
- /usr/share/ieee-data/mam.csv (28-bit MA-M)
- /usr/share/ieee-data/oui36.csv (36-bit MA-S)
- /usr/share/ieee-data/iab.csv (36-bit IAB)
- /usr/share/nmap/nmap-mac-prefixes
- /usr/share/arp-scan/ieee-oui.txt
Plus modern post-2022 IEEE registrations, LAA Virtual BSSID bit-flipping, and SLAAC EUI-64 unmasking.
"""

from __future__ import annotations

import csv
import ipaddress
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MACIntelligence:
    mac: str
    normalized_hex: str
    oui_prefix: str
    vendor: str
    vendor_address: str
    registry_type: str  # MA-L (24-bit), MA-M (28-bit), MA-S (36-bit), IAB, Nmap, Modern-OUI, Locally-Administered
    is_locally_administered: bool
    is_multicast: bool
    randomization_profile: Optional[str]
    unmasked_parent_oui: Optional[str] = None
    unmasked_parent_vendor: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Modern post-2022 IEEE OUI allocations frequently seen on consumer/ISP/enterprise/IoT gear
MODERN_OUI_OVERRIDES: Dict[str, Tuple[str, str]] = {
    "18A5FF": ("Arcadyan Technology Corporation", "No.8, Sec.2, Guangfu Rd., Hsinchu 30071, TW"),
    "186041": ("Arcadyan Technology Corporation (T-Mobile 5G)", "No.8, Sec.2, Guangfu Rd., Hsinchu 30071, TW"),
    "04F778": ("Sony Interactive Entertainment Inc.", "1-7-1 Konan, Minato-ku, Tokyo 108-0075, JP"),
    "F0ED51": ("Hisense Visual Technology Co., Ltd.", "No. 218 Qianwangang Road, Qingdao, Shandong, CN"),
    "E48A93": ("Hisense Visual Technology Co., Ltd.", "No. 218 Qianwangang Road, Qingdao, Shandong, CN"),
    "105932": ("Roku, Inc.", "1155 Coleman Ave, San Jose CA 95110, US"),
    "D83134": ("Roku, Inc.", "1155 Coleman Ave, San Jose CA 95110, US"),
    "84EAED": ("Roku, Inc.", "1155 Coleman Ave, San Jose CA 95110, US"),
    "ACCCFC": ("Amazon Technologies Inc.", "P.O Box 8102, Reno NV 89507, US"),
    "40A2DB": ("Amazon Technologies Inc.", "P.O Box 8102, Reno NV 89507, US"),
    "7C6305": ("Amazon Technologies Inc.", "P.O Box 8102, Reno NV 89507, US"),
    "6854FD": ("Amazon Technologies Inc.", "P.O Box 8102, Reno NV 89507, US"),
    "A8474A": ("Hon Hai Precision Ind. Co., Ltd. (Foxconn)", "No. 2, Ziyou St., Tucheng Dist., New Taipei City, TW"),
    "BC60A7": ("Sony Interactive Entertainment Inc.", "1-7-1 Konan, Minato-ku, Tokyo 108-0075, JP"),
    "E86E3A": ("Sony Interactive Entertainment Inc.", "1-7-1 Konan, Minato-ku, Tokyo 108-0075, JP"),
    "58B03E": ("Nintendo Co., Ltd.", "11-1 Hokotate-cho, Kamitoba, Minami-ku, Kyoto, JP"),
    "00A096": ("Mitsumi Electric Co., Ltd. (Nintendo Wireless)", "2-16-1 Tsurumaki, Tama-shi, Tokyo, JP"),
    "1CBFCE": ("Shenzhen Century Xinyang Technology Co., Ltd.", "Shenzhen, Guangdong, CN"),
    "1C937C": ("ARRIS Group, Inc. / CommScope", "3871 Lakefield Dr, Suwanee GA 30024, US"),
    "704FB8": ("ARRIS Group, Inc. / CommScope", "3871 Lakefield Dr, Suwanee GA 30024, US"),
    "4C22F3": ("Arcadyan Technology Corporation (Verizon 5G)", "No.8, Sec.2, Guangfu Rd., Hsinchu 30071, TW"),
    "3CF083": ("Sagemcom Broadband SAS (T-Mobile Gateway)", "250 Route de l'Empereur, Rueil-Malmaison, FR"),
    "68ABA9": ("Humax Co., Ltd. (AT&T Fiber Gateway)", "Humax Village, Seongnam-si, Gyeonggi-do, KR"),
    "004238": ("Intel Corporate", "Lot 8, Jalan Hi-Tech 2/3, Kulim Kedah 09000, MY"),
    "DCE994": ("Cloud Network Technology Singapore Pte. Ltd. (Foxconn WLAN)", "Singapore, SG"),
    "245A4C": ("Ubiquiti Inc.", "685 Third Avenue, New York NY 10017, US"),
    "7483C2": ("Ubiquiti Inc.", "685 Third Avenue, New York NY 10017, US"),
    "F09FC2": ("Ubiquiti Inc.", "685 Third Avenue, New York NY 10017, US"),
    "DC2C6E": ("MikroTikls SIA", "Brivibas gatve 214i, Riga LV-1039, LV"),
    "2CD8AE": ("Espressif Inc.", "Suite 204, Block 2, 690 Bibo Rd, Shanghai, CN"),
    "348518": ("Espressif Inc.", "Suite 204, Block 2, 690 Bibo Rd, Shanghai, CN"),
    "D8F15B": ("Espressif Inc.", "Suite 204, Block 2, 690 Bibo Rd, Shanghai, CN"),
    "D8A011": ("WiZ Connected / Signify (Philips Hue)", "High Tech Campus 48, Eindhoven, NL"),
    "001788": ("Philips Lighting BV (Signify Hue Bridge)", "High Tech Campus 48, Eindhoven, NL"),
    "ECB5FA": ("Philips Lighting BV (Signify Hue)", "High Tech Campus 48, Eindhoven, NL"),
    "542A1B": ("Sonos, Inc.", "614 Chapala St, Santa Barbara CA 93101, US"),
    "7828CA": ("Sonos, Inc.", "614 Chapala St, Santa Barbara CA 93101, US"),
    "B8E937": ("Sonos, Inc.", "614 Chapala St, Santa Barbara CA 93101, US"),
    "D83ADD": ("Raspberry Pi Trading Ltd", "Maurice Wilkes Building, Cambridge, UK"),
    "2CCF67": ("Raspberry Pi Trading Ltd (Pi 5)", "Maurice Wilkes Building, Cambridge, UK"),
    "B827EB": ("Raspberry Pi Foundation", "Hills Road, Cambridge, UK"),
    "2CAA8E": ("Wyze Labs Inc", "5808 Lake Washington Blvd NE, Kirkland WA, US"),
    "7C78B2": ("Wyze Labs Inc", "5808 Lake Washington Blvd NE, Kirkland WA, US"),
    "EC71DB": ("Reolink Innovation Limited", "Wan Chai, Hong Kong, HK"),
    "001132": ("Synology Incorporated", "9F, No. 1, Yuandong Rd, Banqiao, New Taipei, TW"),
    "245EBE": ("QNAP Systems, Inc.", "2F, No. 22, Zhongxing Rd, Xizhi Dist, New Taipei, TW"),
    "74ACB9": ("SpaceX Services, Inc. (Starlink)", "1 Rocket Road, Hawthorne CA 90250, US"),
}


class OUIDatabase:
    """Comprehensive multi-tier IEEE MAC OUI resolver & vendor search engine."""

    def __init__(self) -> None:
        self.mal_24: Dict[str, Tuple[str, str]] = {}  # 6 hex chars (24-bit)
        self.mam_28: Dict[str, Tuple[str, str]] = {}  # 7 hex chars (28-bit)
        self.mas_36: Dict[str, Tuple[str, str]] = {}  # 9 hex chars (36-bit)
        self.loaded_count: int = 0
        self._load_all()

    def _load_csv(self, path: str, target_dict: Dict[str, Tuple[str, str]], prefix_len: int) -> None:
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 3:
                        assignment = row[1].strip().upper().replace(":", "").replace("-", "")
                        org_name = row[2].strip()
                        org_addr = row[3].strip() if len(row) >= 4 else ""
                        if len(assignment) == prefix_len and org_name:
                            target_dict[assignment] = (org_name, org_addr)
        except Exception:
            pass

    def _load_all(self) -> None:
        # 1. Load IEEE official CSV registries (36-bit, 28-bit, 24-bit)
        self._load_csv("/usr/share/ieee-data/oui36.csv", self.mas_36, 9)
        self._load_csv("/usr/share/ieee-data/iab.csv", self.mas_36, 9)
        self._load_csv("/usr/share/ieee-data/mam.csv", self.mam_28, 7)
        self._load_csv("/usr/share/ieee-data/oui.csv", self.mal_24, 6)

        # 2. Supplement with /usr/share/arp-scan/ieee-oui.txt
        arp_oui = "/usr/share/arp-scan/ieee-oui.txt"
        if os.path.exists(arp_oui):
            try:
                with open(arp_oui, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split("\t", 1)
                            if len(parts) == 2:
                                prefix = parts[0].strip().upper()
                                vendor = parts[1].strip()
                                if len(prefix) == 6 and prefix not in self.mal_24:
                                    self.mal_24[prefix] = (vendor, "")
            except Exception:
                pass

        # 3. Supplement with /usr/share/nmap/nmap-mac-prefixes
        nmap_oui = "/usr/share/nmap/nmap-mac-prefixes"
        if os.path.exists(nmap_oui):
            try:
                with open(nmap_oui, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(maxsplit=1)
                            if len(parts) == 2:
                                prefix = parts[0].strip().upper()
                                vendor = parts[1].strip()
                                if len(prefix) == 6 and prefix not in self.mal_24:
                                    self.mal_24[prefix] = (vendor, "")
            except Exception:
                pass

        # 4. Apply modern post-2022 OUI overrides
        for prefix, (vendor, addr) in MODERN_OUI_OVERRIDES.items():
            self.mal_24[prefix] = (vendor, addr)

        self.loaded_count = len(self.mal_24) + len(self.mam_28) + len(self.mas_36)

    def lookup(self, mac: str) -> MACIntelligence:
        clean = mac.strip().upper().replace(":", "").replace("-", "").replace(".", "")
        if len(clean) < 6 or not all(c in "0123456789ABCDEF" for c in clean[:6]):
            return MACIntelligence(
                mac=mac.upper(),
                normalized_hex=clean,
                oui_prefix="",
                vendor="Unknown Hardware",
                vendor_address="",
                registry_type="Invalid",
                is_locally_administered=False,
                is_multicast=False,
                randomization_profile=None,
            )

        formatted_mac = ":".join(clean[i : i + 2] for i in range(0, min(len(clean), 12), 2))
        first_octet = int(clean[:2], 16)
        is_multicast = bool(first_octet & 0x01)
        is_locally_admin = bool(first_octet & 0x02)

        # Check 36-bit MA-S / IAB first
        if len(clean) >= 9 and clean[:9] in self.mas_36:
            v_name, v_addr = self.mas_36[clean[:9]]
            return MACIntelligence(
                mac=formatted_mac,
                normalized_hex=clean,
                oui_prefix=f"{clean[:2]}:{clean[2:4]}:{clean[4:6]}:{clean[6:8]}:{clean[8]}0/36",
                vendor=v_name,
                vendor_address=v_addr,
                registry_type="IEEE MA-S / IAB (36-bit)",
                is_locally_administered=is_locally_admin,
                is_multicast=is_multicast,
                randomization_profile=None,
            )

        # Check 28-bit MA-M second
        if len(clean) >= 7 and clean[:7] in self.mam_28:
            v_name, v_addr = self.mam_28[clean[:7]]
            return MACIntelligence(
                mac=formatted_mac,
                normalized_hex=clean,
                oui_prefix=f"{clean[:2]}:{clean[2:4]}:{clean[4:6]}:{clean[6]}0/28",
                vendor=v_name,
                vendor_address=v_addr,
                registry_type="IEEE MA-M (28-bit)",
                is_locally_administered=is_locally_admin,
                is_multicast=is_multicast,
                randomization_profile=None,
            )

        # Check 24-bit MA-L third
        prefix6 = clean[:6]
        oui_colon = f"{clean[:2]}:{clean[2:4]}:{clean[4:6]}"
        if prefix6 in self.mal_24:
            v_name, v_addr = self.mal_24[prefix6]
            reg_type = "IEEE Modern Allocation" if prefix6 in MODERN_OUI_OVERRIDES else "IEEE MA-L (24-bit)"
            return MACIntelligence(
                mac=formatted_mac,
                normalized_hex=clean,
                oui_prefix=oui_colon,
                vendor=v_name,
                vendor_address=v_addr,
                registry_type=reg_type,
                is_locally_administered=is_locally_admin,
                is_multicast=is_multicast,
                randomization_profile=None,
            )

        # If not found in IEEE registry, analyze Locally Administered / Randomized MAC bit
        if is_locally_admin:
            second_nibble = clean[1]
            # Check if flipping the U/L bit (first_octet & 0xFD) reveals a registered parent OUI (Virtual BSSID / Wi-Fi Direct)
            unmasked_b0 = first_octet & 0xFD
            unmasked_prefix6 = f"{unmasked_b0:02X}{clean[2:6]}"
            unmasked_colon = f"{unmasked_b0:02X}:{clean[2:4]}:{clean[4:6]}"
            parent_vendor: Optional[str] = None
            if unmasked_prefix6 in self.mal_24:
                parent_vendor = self.mal_24[unmasked_prefix6][0]

            rand_profile = "Mobile OS Per-SSID Private MAC (iOS / Android)"
            if parent_vendor:
                rand_profile = f"LAA Virtual BSSID / Wi-Fi Direct derived from {parent_vendor} ({unmasked_colon})"
            elif clean.startswith("02"):
                rand_profile = "Virtual / Container / P2P Locally Administered MAC"
            return MACIntelligence(
                mac=formatted_mac,
                normalized_hex=clean,
                oui_prefix=oui_colon,
                vendor="Private / Randomized Hardware Address",
                vendor_address=f"IEEE 802.11 Privacy MAC (U/L Bit=1, Nibble=0x{second_nibble})",
                registry_type="Locally Administered (LAA)",
                is_locally_administered=True,
                is_multicast=is_multicast,
                randomization_profile=rand_profile,
                unmasked_parent_oui=unmasked_colon if parent_vendor else None,
                unmasked_parent_vendor=parent_vendor,
            )

        return MACIntelligence(
            mac=formatted_mac,
            normalized_hex=clean,
            oui_prefix=oui_colon,
            vendor="Unregistered / Newly Allocated IEEE OUI",
            vendor_address="",
            registry_type="Unlisted OUI",
            is_locally_administered=False,
            is_multicast=is_multicast,
            randomization_profile=None,
        )

    def search(self, query: str, limit: int = 40) -> Dict[str, Any]:
        """
        Multi-modal IEEE OUI & Hardware Intelligence Search:
        1. If `query` is an IPv6 SLAAC EUI-64 address, unmasks the burned-in 48-bit MAC & OUI.
        2. If `query` is a MAC address or OUI hex prefix, performs direct `lookup()` + prefix matches.
        3. Otherwise searches vendor names & addresses across all 47,000+ IEEE registries.
        """
        q_raw = (query or "").strip()
        if not q_raw:
            return {"query": "", "total_loaded": self.loaded_count, "matches": []}

        # 1. Check IPv6 SLAAC EUI-64 address
        if ":" in q_raw and ("fe80" in q_raw.lower() or "ff:fe" in q_raw.lower() or q_raw.count(":") >= 4 and len(q_raw) > 17):
            eui = unmask_eui64_ipv6_mac([q_raw])
            if eui:
                rec_mac, intel = eui
                item = {
                    "prefix": intel.oui_prefix,
                    "oui_prefix": intel.oui_prefix,
                    "ipv6": q_raw,
                    "unmasked_mac": rec_mac,
                    "vendor": intel.vendor,
                    "address": intel.vendor_address,
                    "registry": intel.registry_type,
                    "registry_type": intel.registry_type,
                }
                return {
                    "ok": True,
                    "query": q_raw,
                    "mode": "ipv6_eui64_unmask",
                    "recovered_mac": rec_mac,
                    "total_matches": 1,
                    "direct_lookup": intel.to_dict(),
                    "matches": [item],
                    "results": [item],
                }

        # 2. Check MAC or hex OUI prefix
        clean_hex = q_raw.upper().replace(":", "").replace("-", "").replace(".", "").strip()
        direct: Optional[Dict[str, Any]] = None
        matches: List[Dict[str, Any]] = []
        if len(clean_hex) >= 6 and all(c in "0123456789ABCDEF" for c in clean_hex):
            direct = self.lookup(q_raw).to_dict()
            d_copy = dict(direct)
            d_copy["prefix"] = direct.get("mac") or direct.get("oui_prefix") or q_raw
            d_copy["address"] = direct.get("vendor_address", "")
            d_copy["registry"] = direct.get("registry_type", "IEEE MA-L (24-bit)")
            matches.append(d_copy)

        q_lower = q_raw.lower()

        if len(clean_hex) >= 4 and all(c in "0123456789ABCDEF" for c in clean_hex):
            p_check = clean_hex[:6]
            for k, (v_name, v_addr) in self.mal_24.items():
                if k.startswith(p_check[: min(6, len(p_check))]):
                    colon_p = f"{k[:2]}:{k[2:4]}:{k[4:6]}"
                    if not any(m.get("oui_prefix") == colon_p for m in matches):
                        matches.append({
                            "prefix": colon_p,
                            "oui_prefix": colon_p,
                            "vendor": v_name,
                            "address": v_addr,
                            "vendor_address": v_addr,
                            "registry": "IEEE MA-L (24-bit)",
                            "registry_type": "IEEE MA-L (24-bit)",
                        })
                    if len(matches) >= limit:
                        break

        if len(matches) < limit:
            for k, (v_name, v_addr) in self.mal_24.items():
                if q_lower in v_name.lower() or (v_addr and q_lower in v_addr.lower()):
                    colon_p = f"{k[:2]}:{k[2:4]}:{k[4:6]}"
                    reg_str = "IEEE Modern Allocation" if k in MODERN_OUI_OVERRIDES else "IEEE MA-L (24-bit)"
                    matches.append({
                        "prefix": colon_p,
                        "oui_prefix": colon_p,
                        "vendor": v_name,
                        "address": v_addr,
                        "vendor_address": v_addr,
                        "registry": reg_str,
                        "registry_type": reg_str,
                    })
                    if len(matches) >= limit:
                        break

        if len(matches) < limit:
            for k, (v_name, v_addr) in self.mam_28.items():
                if q_lower in v_name.lower():
                    colon_p = f"{k[:2]}:{k[2:4]}:{k[4:6]}:{k[6]}0/28"
                    matches.append({
                        "prefix": colon_p,
                        "oui_prefix": colon_p,
                        "vendor": v_name,
                        "address": v_addr,
                        "vendor_address": v_addr,
                        "registry": "IEEE MA-M (28-bit)",
                        "registry_type": "IEEE MA-M (28-bit)",
                    })
                    if len(matches) >= limit:
                        break

        return {
            "ok": True,
            "query": q_raw,
            "mode": "mac_lookup" if direct else "vendor_search",
            "total_loaded": self.loaded_count,
            "total_matches": len(matches),
            "direct_lookup": direct,
            "matches": matches,
            "results": matches,
        }


# Singleton instance
oui_db = OUIDatabase()


def unmask_eui64_ipv6_mac(ipv6_addresses: List[str]) -> Optional[Tuple[str, MACIntelligence]]:
    """
    Extract burned-in IEEE 48-bit universal hardware MAC from SLAAC EUI-64 IPv6 addresses
    (e.g., fe80::uuvv:wwff:fexx:yyzz -> invert bit 0x02 of uu -> UU:VV:WW:XX:YY:ZZ).
    Used to de-anonymize hosts using Locally Administered (U/L=1) randomized IPv4 MACs.
    """
    for raw_v6 in ipv6_addresses:
        clean_v6 = raw_v6.split("%")[0].split("/")[0].strip()
        try:
            addr = ipaddress.IPv6Address(clean_v6)
            raw_bytes = addr.packed
            # Interface ID is last 8 bytes (bytes 8..15); EUI-64 has 0xFF 0xFE at bytes 11 and 12
            if len(raw_bytes) == 16 and raw_bytes[11] == 0xFF and raw_bytes[12] == 0xFE:
                b0 = raw_bytes[8] ^ 0x02
                mac_bytes = [b0, raw_bytes[9], raw_bytes[10], raw_bytes[13], raw_bytes[14], raw_bytes[15]]
                recovered_mac = ":".join(f"{b:02X}" for b in mac_bytes)
                intel = oui_db.lookup(recovered_mac)
                return (recovered_mac, intel)
        except Exception:
            continue
    return None
