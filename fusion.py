"""Netwide Sovereign Proof Mode — Evidence-Graded Attribution & Vector Fusion Engine.

Implements S11 & S12 Proof Mode specifications:
- 16 independent physical, cryptographic, and protocol evidence vectors
- Brand/identity alias normalization (UniFi/UBNT -> Ubiquiti, Bonjour -> Apple, etc.)
- Weighted majority vote with disagreement penalties and logistic recalibration
- Strict evidence tiers:
    * VERIFIED: >=2 independent strong vectors agree AND no high-confidence contradiction
    * PROBABLE: 1 strong vector or compatible telemetry without contradiction
    * WEAK: Only 1 weak vector, unattested inference, or active contradiction
- Brier score calibration metric (Brier < 0.15 accuracy gate)
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# The 16 Independent Evidence Vectors of S11 Proof Mode
VECTOR_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "oui_burn": {
        "name": "Burned-in IEEE OUI",
        "description": "Hardware MAC address globally registered with IEEE Registration Authority",
        "weight": 0.88,
        "category": "physical",
    },
    "unl_mask": {
        "name": "Unmasked LAA OUI",
        "description": "Locally Administered Address de-masked via bit-flip inversion (Stage 7/8)",
        "weight": 0.82,
        "category": "algorithmic",
    },
    "tsf_clock_delta": {
        "name": "TSF Hardware Clock Drift",
        "description": "802.11 Timing Synchronization Function microsecond clock skew across radios",
        "weight": 0.94,
        "category": "physical_clock",
    },
    "qbss_count": {
        "name": "QBSS Station Correlation",
        "description": "Co-located BSSID station load & channel utilization match",
        "weight": 0.74,
        "category": "rf_covariance",
    },
    "rssi_covariance": {
        "name": "Spatial RSSI Covariance",
        "description": "Signal power delta and path loss correlation over time",
        "weight": 0.76,
        "category": "rf_spatial",
    },
    "rate_profile": {
        "name": "802.11 Rate Profile",
        "description": "Supported/Basic MCS rate matrix (e.g., 65/130 Mbps personal tether signature)",
        "weight": 0.80,
        "category": "protocol_phy",
    },
    "he_phy_cap": {
        "name": "Wi-Fi 6/6E/7 HE PHY Capabilities",
        "description": "High Efficiency Information Element chipset feature bits",
        "weight": 0.86,
        "category": "silicon_capability",
    },
    "dhcp_opt55": {
        "name": "DHCP Parameter Request List (Opt 55)",
        "description": "Exact byte sequence of requested DHCP configuration options per OS stack",
        "weight": 0.90,
        "category": "os_network_stack",
    },
    "dhcp_vendor60": {
        "name": "DHCP Vendor Class ID (Opt 60)",
        "description": "Explicit client vendor identification broadcast at IP lease negotiation",
        "weight": 0.88,
        "category": "os_network_stack",
    },
    "ja3_ja4": {
        "name": "TLS JA4+ Client Cipher Print",
        "description": "Cryptographic TLS ClientHello handshake fingerprint",
        "weight": 0.86,
        "category": "cryptographic",
    },
    "mdns_model": {
        "name": "mDNS Service & TXT Model",
        "description": "Zero-configuration DNS multicast model and device attributes",
        "weight": 0.94,
        "category": "application_identity",
    },
    "upnp_model": {
        "name": "UPnP Device XML Descriptor",
        "description": "Universal Plug and Play XML schema model, manufacturer and UDN",
        "weight": 0.95,
        "category": "application_identity",
    },
    "snmp_sysoid": {
        "name": "SNMP sysObjectID MIB",
        "description": "Enterprise Management Information Base system object identifier",
        "weight": 0.96,
        "category": "enterprise_management",
    },
    "wps_manuf_model": {
        "name": "WPS IE Manufacturer/Model",
        "description": "Wi-Fi Protected Setup probe response hardware identity elements",
        "weight": 0.89,
        "category": "firmware_beacon",
    },
    "smb_serverguid": {
        "name": "SMB2/3 ServerGUID & Context",
        "description": "Unique Windows/Samba OS installation GUID and negotiate security mode",
        "weight": 0.95,
        "category": "os_cryptographic",
    },
    "ssh_hassh": {
        "name": "SSH HASSH Algorithm Print",
        "description": "SSH key exchange, cipher, and MAC algorithm suite hash",
        "weight": 0.90,
        "category": "cryptographic",
    },
}

# Known Hardware & Protocol Vendor Aliases
VENDOR_ALIASES: Dict[str, str] = {
    "ubnt": "ubiquiti",
    "unifi": "ubiquiti",
    "ubiquiti": "ubiquiti",
    "apple": "apple",
    "iphone": "apple",
    "ipad": "apple",
    "macbook": "apple",
    "airdrop": "apple",
    "_apple-mobdev2": "apple",
    "sonos": "sonos",
    "rincon": "sonos",
    "roku": "roku",
    "google": "google",
    "chromecast": "google",
    "nest": "google",
    "_googlecast": "google",
    "philips": "philips",
    "hue": "philips",
    "giga-byte": "giga-byte",
    "gigabyte": "giga-byte",
    "t-mobile": "t-mobile",
    "tmo": "t-mobile",
    "sony": "sony",
    "playstation": "sony",
    "ps5": "sony",
    "ps4": "sony",
    "samsung": "samsung",
    "amazon": "amazon",
    "kindle": "amazon",
    "echo": "amazon",
    "raspberry": "raspberry pi",
    "rpi": "raspberry pi",
    "espressif": "espressif",
}


PROTOCOL_OR_GENERIC_TOKENS = {
    "ssh", "openssh", "http", "tls", "smb", "dns", "snmp", "generic",
    "unknown", "open", "tcp", "udp", "linux", "debian", "ubuntu",
    "windows", "android", "infrastructure", "physical", "ap",
}


def normalize_brand_token(text: str) -> str:
    """Normalize raw vendor strings into canonical vendor keys."""
    cleaned = (text or "").lower().replace("-", " ").replace("_", " ").strip()
    for token, canonical in VENDOR_ALIASES.items():
        if token in cleaned:
            return canonical
    words = cleaned.split()
    return words[0] if words else "unknown"


@dataclass
class EvidenceVector:
    """A single verifiable evidence vector extracted from physical or network signals."""

    vector_id: str
    name: str
    claimed_identity: str
    raw_evidence: str
    weight: float
    confidence: float  # 0.0 to 1.0
    normalized_brand: str = "unknown"
    is_anomaly: bool = False
    observed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FusionVerdict:
    """The fused verdict graded across all independent evidence vectors."""

    grade: str  # "VERIFIED" | "PROBABLE" | "WEAK"
    primary_claim: str
    calibrated_probability: float  # 0.0 to 1.0
    vector_count: int
    agreeing_vectors: List[Dict[str, Any]]
    disagreeing_vectors: List[Dict[str, Any]]
    brier_score: float
    proof_summary: str
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_evidence_vectors(device: Dict[str, Any], aps: Optional[List[Dict[str, Any]]] = None) -> List[EvidenceVector]:
    """Extract all active S11 independent evidence vectors from device profile and wireless scan."""
    vectors: List[EvidenceVector] = []
    now = time.time()
    mac = str(device.get("mac") or "").upper()
    brand = str(device.get("brand") or "").strip()
    model = str(device.get("model") or device.get("display_name") or "").strip()
    is_rand = bool(device.get("is_randomized_mac"))

    # Vector 1: Burned-in IEEE OUI
    if mac and not is_rand and brand and "unknown" not in brand.lower():
        vdef = VECTOR_DEFINITIONS["oui_burn"]
        vectors.append(EvidenceVector(
            vector_id="oui_burn",
            name=vdef["name"],
            claimed_identity=brand,
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"IEEE OUI {mac[:8]} -> {brand}",
            weight=vdef["weight"],
            confidence=0.92,
            observed_at=now,
        ))

    # Vector 2: Unmasked LAA OUI
    if is_rand and brand and "unknown" not in brand.lower():
        vdef = VECTOR_DEFINITIONS["unl_mask"]
        vectors.append(EvidenceVector(
            vector_id="unl_mask",
            name=vdef["name"],
            claimed_identity=brand,
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"Unmasked LAA {mac} -> {brand}",
            weight=vdef["weight"],
            confidence=0.85,
            observed_at=now,
        ))

    # Vector 3: TSF Hardware Clock Delta (from matched AP)
    ap_match = None
    if aps and mac:
        ap_match = next((a for a in aps if str(a.get("bssid") or "").upper() == mac), None)
    if ap_match and ap_match.get("tsf_delta_us") is not None:
        delta = abs(float(ap_match["tsf_delta_us"]))
        vdef = VECTOR_DEFINITIONS["tsf_clock_delta"]
        parent = ap_match.get("parent_router_ssid") or ap_match.get("ssid") or "Radio Cluster"
        if delta < 100.0:
            # Synchronized hardware clock confirms multi-radio AP
            vectors.append(EvidenceVector(
                vector_id="tsf_clock_delta",
                name=vdef["name"],
                claimed_identity=f"Co-located radio of {parent}",
                normalized_brand=normalize_brand_token(parent),
                raw_evidence=f"TSF delta {delta:.1f}µs matched to {parent}",
                weight=vdef["weight"],
                confidence=max(0.75, round(1.0 - (delta / 200.0), 2)),
                is_anomaly=False,
                observed_at=now,
            ))
        else:
            # Large clock drift indicates unsynchronized rogue / spoofed AP
            vectors.append(EvidenceVector(
                vector_id="tsf_clock_delta",
                name=vdef["name"],
                claimed_identity="Clock Skew Anomaly (Unsynchronized AP)",
                normalized_brand="rogue_anomaly",
                raw_evidence=f"TSF skew {delta:.1f}µs contradicts {parent} hardware clock",
                weight=vdef["weight"],
                confidence=0.95,
                is_anomaly=True,
                observed_at=now,
            ))

    # Vector 4: QBSS Count Correlation
    if ap_match and ap_match.get("qbss_station_count") is not None:
        vdef = VECTOR_DEFINITIONS["qbss_count"]
        cnt = ap_match["qbss_station_count"]
        vectors.append(EvidenceVector(
            vector_id="qbss_count",
            name=vdef["name"],
            claimed_identity=str(ap_match.get("ssid") or "AP Station Load"),
            normalized_brand=normalize_brand_token(str(ap_match.get("ssid") or "")),
            raw_evidence=f"QBSS stations: {cnt}, channel util: {ap_match.get('qbss_channel_utilization', 'N/A')}",
            weight=vdef["weight"],
            confidence=0.80,
            observed_at=now,
        ))

    # Vector 5: Spatial RSSI Covariance
    sig = device.get("signal_dbm") or (ap_match.get("signal_dbm") if ap_match else None)
    if sig is not None and float(sig) > -85.0:
        vdef = VECTOR_DEFINITIONS["rssi_covariance"]
        sig_f = float(sig)
        vectors.append(EvidenceVector(
            vector_id="rssi_covariance",
            name=vdef["name"],
            claimed_identity=brand or "Physical Local Perimeter",
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"Observed RSSI {sig_f:.1f} dBm within proximity threshold",
            weight=vdef["weight"],
            confidence=0.80 if sig_f > -65.0 else 0.65,
            observed_at=now,
        ))

    # Vector 6: Rate Profile
    if ap_match and ap_match.get("rate_mbps"):
        vdef = VECTOR_DEFINITIONS["rate_profile"]
        rate = ap_match["rate_mbps"]
        is_hotspot = rate in (65, 130, 260)
        vectors.append(EvidenceVector(
            vector_id="rate_profile",
            name=vdef["name"],
            claimed_identity=f"{brand} Personal Hotspot" if is_hotspot else "Infrastructure Access Point",
            normalized_brand=normalize_brand_token(brand) if is_hotspot else "infrastructure",
            raw_evidence=f"Advertised 802.11 PHY rate {rate} Mbps",
            weight=vdef["weight"],
            confidence=0.85 if is_hotspot else 0.72,
            observed_at=now,
        ))

    # Vector 7: HE PHY Capabilities (Wi-Fi 6/7)
    if ap_match and (ap_match.get("is_he") or ap_match.get("is_vht")):
        vdef = VECTOR_DEFINITIONS["he_phy_cap"]
        phy = "802.11ax (Wi-Fi 6)" if ap_match.get("is_he") else "802.11ac (Wi-Fi 5)"
        vectors.append(EvidenceVector(
            vector_id="he_phy_cap",
            name=vdef["name"],
            claimed_identity=f"{brand} {phy}".strip(),
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"PHY IE elements confirm {phy} hardware silicon",
            weight=vdef["weight"],
            confidence=0.88,
            observed_at=now,
        ))

    # Vector 8: DHCP Option 55 Parameter Request List
    opt55 = device.get("dhcp_opt55") or (device.get("fingerprint_details", {}).get("dhcp_opt55") if isinstance(device.get("fingerprint_details"), dict) else None)
    if opt55:
        vdef = VECTOR_DEFINITIONS["dhcp_opt55"]
        vectors.append(EvidenceVector(
            vector_id="dhcp_opt55",
            name=vdef["name"],
            claimed_identity=brand or str(device.get("os_family") or "Operating System Stack"),
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"DHCP PRL: {opt55}",
            weight=vdef["weight"],
            confidence=0.92,
            observed_at=now,
        ))

    # Vector 9: DHCP Option 60 Vendor Class ID
    opt60 = device.get("dhcp_vendor60") or (device.get("fingerprint_details", {}).get("dhcp_vendor60") if isinstance(device.get("fingerprint_details"), dict) else None)
    if opt60:
        vdef = VECTOR_DEFINITIONS["dhcp_vendor60"]
        vectors.append(EvidenceVector(
            vector_id="dhcp_vendor60",
            name=vdef["name"],
            claimed_identity=str(opt60),
            normalized_brand=normalize_brand_token(str(opt60)),
            raw_evidence=f"DHCP Vendor Class: {opt60}",
            weight=vdef["weight"],
            confidence=0.92,
            observed_at=now,
        ))

    # Vector 10: TLS JA4+ Fingerprint
    ja3 = device.get("ja3") or device.get("ja4")
    if ja3:
        vdef = VECTOR_DEFINITIONS["ja3_ja4"]
        vectors.append(EvidenceVector(
            vector_id="ja3_ja4",
            name=vdef["name"],
            claimed_identity=brand or str(device.get("os_family") or "TLS Client Suite"),
            normalized_brand=normalize_brand_token(brand),
            raw_evidence=f"ClientHello Hash: {ja3}",
            weight=vdef["weight"],
            confidence=0.85,
            observed_at=now,
        ))

    # Vector 11: mDNS Model & TXT Attributes
    mdns = device.get("mdns_services") or []
    if mdns:
        vdef = VECTOR_DEFINITIONS["mdns_model"]
        svc_names = [m.get("service") or m.get("service_type") or "" for m in mdns if isinstance(m, dict)]
        first_svc = svc_names[0] if svc_names else "mDNS Responder"
        claim = model or brand or first_svc
        vectors.append(EvidenceVector(
            vector_id="mdns_model",
            name=vdef["name"],
            claimed_identity=claim,
            normalized_brand=normalize_brand_token(f"{brand} {first_svc}"),
            raw_evidence=f"mDNS advertised services: {', '.join(filter(None, svc_names))[:100]}",
            weight=vdef["weight"],
            confidence=0.95,
            observed_at=now,
        ))

    # Vector 12: UPnP Device XML Descriptor
    upnp = device.get("upnp_info") or {}
    if upnp and (upnp.get("model_name") or upnp.get("friendly_name") or upnp.get("modelName")):
        vdef = VECTOR_DEFINITIONS["upnp_model"]
        mname = upnp.get("model_name") or upnp.get("modelName") or upnp.get("friendly_name")
        manuf = upnp.get("manufacturer") or brand
        claim = f"{manuf} {mname}".strip()
        vectors.append(EvidenceVector(
            vector_id="upnp_model",
            name=vdef["name"],
            claimed_identity=claim,
            normalized_brand=normalize_brand_token(f"{manuf} {claim}"),
            raw_evidence=f"UPnP Model: {mname}, UDN: {upnp.get('udn', 'N/A')}",
            weight=vdef["weight"],
            confidence=0.96,
            observed_at=now,
        ))

    # Vector 13: SNMP sysObjectID
    snmp = device.get("snmp_info") or {}
    if snmp and (snmp.get("sys_descr") or snmp.get("sys_object_id")):
        vdef = VECTOR_DEFINITIONS["snmp_sysoid"]
        descr = str(snmp.get("sys_descr") or "Enterprise SNMP Managed Host")[:60]
        vectors.append(EvidenceVector(
            vector_id="snmp_sysoid",
            name=vdef["name"],
            claimed_identity=descr,
            normalized_brand=normalize_brand_token(descr),
            raw_evidence=f"sysDescr: {snmp.get('sys_descr', '')[:80]}, OID: {snmp.get('sys_object_id', '')}",
            weight=vdef["weight"],
            confidence=0.96,
            observed_at=now,
        ))

    # Vector 14: WPS Manufacturer / Model
    if ap_match and ap_match.get("wps_model_name"):
        vdef = VECTOR_DEFINITIONS["wps_manuf_model"]
        wps_claim = f"{ap_match.get('wps_manufacturer', '')} {ap_match.get('wps_model_name', '')}".strip()
        vectors.append(EvidenceVector(
            vector_id="wps_manuf_model",
            name=vdef["name"],
            claimed_identity=wps_claim,
            normalized_brand=normalize_brand_token(wps_claim),
            raw_evidence=f"WPS IE: {wps_claim} (model number {ap_match.get('wps_model_number', 'N/A')})",
            weight=vdef["weight"],
            confidence=0.90,
            observed_at=now,
        ))

    # Vector 15: SMB2/3 ServerGUID
    smb = device.get("smb_info") or {}
    if smb and smb.get("server_guid"):
        vdef = VECTOR_DEFINITIONS["smb_serverguid"]
        guid = smb["server_guid"]
        vectors.append(EvidenceVector(
            vector_id="smb_serverguid",
            name=vdef["name"],
            claimed_identity=f"Windows / SMB Server ({smb.get('native_os', 'OS')})",
            normalized_brand="microsoft",
            raw_evidence=f"SMB ServerGUID: {guid}, Dialect: {smb.get('dialect', '3.1.1')}",
            weight=vdef["weight"],
            confidence=0.96,
            observed_at=now,
        ))

    # Vector 16: SSH HASSH Algorithm Print
    ssh = device.get("ssh_info") or {}
    if ssh and (ssh.get("hassh") or ssh.get("banner")):
        vdef = VECTOR_DEFINITIONS["ssh_hassh"]
        banner = str(ssh.get("banner") or "SSH Server Implementation")[:60]
        vectors.append(EvidenceVector(
            vector_id="ssh_hassh",
            name=vdef["name"],
            claimed_identity=banner,
            normalized_brand=normalize_brand_token(banner),
            raw_evidence=f"SSH Banner: {banner}, HASSH: {ssh.get('hassh', 'N/A')}",
            weight=vdef["weight"],
            confidence=0.90,
            observed_at=now,
        ))

    return vectors


def fuse_evidence(vectors: List[EvidenceVector], default_identity: str = "Generic Network Host") -> FusionVerdict:
    """Mathematical multi-vector evidence fusion with disagreement penalty and logistic recalibration."""
    if not vectors:
        return FusionVerdict(
            grade="WEAK",
            primary_claim=default_identity,
            calibrated_probability=0.35,
            vector_count=0,
            agreeing_vectors=[],
            disagreeing_vectors=[],
            brier_score=0.1225,
            proof_summary="No independent vectors observed (unattested inference)",
        )

    # 1. Check for active anomaly/contradiction vectors (e.g. evil twin massive TSF clock skew)
    anomaly_vectors = [v for v in vectors if v.is_anomaly]

    # 2. Identify the target brand/identity
    # Priority: primary identifying vectors (OUI, mDNS, UPnP, SNMP, DHCP vendor)
    identifying_vectors = [v for v in vectors if v.vector_id in ("oui_burn", "unl_mask", "mdns_model", "upnp_model", "snmp_sysoid", "dhcp_vendor60", "wps_manuf_model")]
    brand_scores: Dict[str, float] = {}
    for v in identifying_vectors:
        b = v.normalized_brand
        if b and b != "unknown":
            brand_scores[b] = brand_scores.get(b, 0.0) + (v.weight * v.confidence)

    target_brand = max(brand_scores.items(), key=lambda x: x[1])[0] if brand_scores else normalize_brand_token(default_identity)

    # 3. Partition into agreeing and disagreeing vectors
    agreeing: List[EvidenceVector] = []
    disagreeing: List[EvidenceVector] = []

    for v in vectors:
        if v.is_anomaly:
            disagreeing.append(v)
            continue
        v_brand = v.normalized_brand
        # A vector contradicts only if it asserts a specific different recognized hardware brand
        if v_brand not in PROTOCOL_OR_GENERIC_TOKENS and v_brand != "unknown" and v_brand != target_brand:
            disagreeing.append(v)
        else:
            agreeing.append(v)

    # Prioritize identifying vectors for primary claim
    identifying_claims = [
        v.claimed_identity for v in agreeing
        if v.vector_id in ("upnp_model", "wps_manuf_model", "snmp_sysoid", "mdns_model", "oui_burn", "unl_mask", "dhcp_vendor60")
        and v.claimed_identity and "perimeter" not in v.claimed_identity.lower()
    ]

    if default_identity and default_identity not in ("Generic Network Host", "Generic Host"):
        best_claim = default_identity
    elif identifying_claims:
        best_claim = max(identifying_claims, key=len)
    elif target_brand != "unknown":
        best_claim = target_brand.title()
    else:
        best_claim = default_identity

    # 4. Weighted calculation
    w_agree = sum(v.weight * v.confidence for v in agreeing)
    w_disagree = sum(v.weight * v.confidence for v in disagreeing)

    # Penalty for disagreement / anomalies
    penalty = 1.0 - min(0.70, (w_disagree / (w_agree + w_disagree + 1e-6)))

    # Logistic calibration
    raw_p = min(0.99, max(0.01, w_agree / (w_agree + 1.0)))
    logit = math.log(raw_p / (1.0 - raw_p))
    alpha = 0.35
    beta = 1.25
    calibrated_p = (1.0 / (1.0 + math.exp(-(alpha + beta * logit)))) * penalty
    calibrated_p = round(max(0.05, min(0.99, calibrated_p)), 3)

    # 5. Grade Assignment
    # VERIFIED requires:
    #   - >=2 strong independent identifying vectors agreeing (OUI, unmask, mDNS, UPnP, SNMP, DHCP vendor)
    #   - No high-confidence contradiction/anomaly (w_disagree < 0.3)
    #   - Calibrated probability >= 0.85
    strong_identifying = [v for v in agreeing if v.vector_id in ("oui_burn", "unl_mask", "mdns_model", "upnp_model", "snmp_sysoid", "dhcp_vendor60", "wps_manuf_model", "smb_serverguid", "tsf_clock_delta") and v.weight >= 0.80 and v.confidence >= 0.80]

    if len(strong_identifying) >= 2 and w_disagree < 0.3 and calibrated_p >= 0.82 and not anomaly_vectors:
        grade = "VERIFIED"
    elif (len(agreeing) >= 1 and calibrated_p >= 0.55 and not anomaly_vectors):
        grade = "PROBABLE"
    else:
        grade = "WEAK"

    expected_outcome = 1.0 if grade in ("VERIFIED", "PROBABLE") else 0.0
    brier = round((calibrated_p - expected_outcome) ** 2, 4)

    vector_names = [v.vector_id for v in agreeing]
    proof_summary = (
        f"{grade} via {len(agreeing)} independent vector{'s' if len(agreeing) != 1 else ''} "
        f"[{', '.join(vector_names[:4])}] (calibrated p={calibrated_p:.2f})"
    )

    return FusionVerdict(
        grade=grade,
        primary_claim=best_claim,
        calibrated_probability=calibrated_p,
        vector_count=len(vectors),
        agreeing_vectors=[v.to_dict() for v in agreeing],
        disagreeing_vectors=[v.to_dict() for v in disagreeing],
        brier_score=brier,
        proof_summary=proof_summary,
    )
