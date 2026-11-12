"""
Multi-Signal Heuristic Device Fingerprinting, Classification & Security Audit Engine.
Synthesizes 12 layers of hardware, link-layer, transport, and application telemetry into:
- Exact Brand, Model, Friendly Name, Hostname, Serial Number, and Firmware Version
- Device Category & Icon Taxonomy
- Power State (ACTIVE / STANDBY / DTIM POWER-SAVE)
- Confidence Score (0-100%) with full forensic reasoning chain
- Security Posture & Vulnerability Audit per device
"""

from __future__ import annotations

import concurrent.futures
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
from netpulse.oui import MACIntelligence, oui_db, unmask_eui64_ipv6_mac
from netpulse.probers import (
    NetworkInterfaceInfo,
    arp_and_neighbor_sweep,
    measure_single_host_latency,
    probe_airplay_bplist,
    probe_dns_security_posture,
    probe_extended_iot_and_infra,
    probe_google_cast_eureka,
    probe_homekit_and_matter,
    probe_mdns_services,
    probe_netbios_and_rdns,
    probe_playstation_ddp,
    probe_roku_ecp,
    probe_smart_iot_and_tv,
    probe_smb2_negotiate,
    probe_snmp_sysinfo,
    probe_spotify_connect,
    probe_ssdp_upnp,
    probe_ssh_kex_and_hostkeys,
    probe_tmobile_gateway,
    quarantine_engine,
    read_kernel_neighbors,
    scan_ports_and_banners,
)


@dataclass
class SecurityFinding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    remediation: str


@dataclass
class DeviceProfile:
    ip: str
    mac: str
    secondary_macs: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    is_local: bool = False
    is_gateway: bool = False
    neigh_state: str = "REACHABLE"

    # Hardware & OUI
    vendor: str = "Unknown Vendor"
    vendor_address: str = ""
    oui_prefix: str = ""
    registry_type: str = ""
    is_randomized_mac: bool = False
    randomization_profile: Optional[str] = None

    # Identity & Classification
    display_name: str = ""
    hostname: str = ""
    brand: str = ""
    model: str = ""
    model_number: str = ""
    serial_number: str = ""
    udn: str = ""
    category: str = "Generic Network Host"
    icon_type: str = "device"  # router, tv, stick, console, speaker, phone, laptop, iot, camera, printer, server
    os_family: str = "Unknown OS"
    firmware_version: str = ""
    hardware_image_url: str = ""

    # Runtime & Network Telemetry
    power_state: str = "ACTIVE"
    active_app: str = ""
    rtt_ms: Optional[float] = None
    rtt_method: str = ""
    ttl: Optional[int] = None
    uptime_seconds: Optional[int] = None
    confidence_score: int = 50
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Deep Protocol Payloads
    hardware_specs: Dict[str, str] = field(default_factory=dict)
    control_capabilities: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    port_services: List[Dict[str, Any]] = field(default_factory=list)
    mdns_services: List[Dict[str, Any]] = field(default_factory=list)
    upnp_info: Dict[str, Any] = field(default_factory=dict)
    roku_info: Dict[str, Any] = field(default_factory=dict)
    airplay_info: Dict[str, Any] = field(default_factory=dict)
    spotify_info: Dict[str, Any] = field(default_factory=dict)
    playstation_info: Dict[str, Any] = field(default_factory=dict)
    gateway_5g_info: Dict[str, Any] = field(default_factory=dict)
    google_cast_info: Dict[str, Any] = field(default_factory=dict)
    homekit_matter_info: Dict[str, Any] = field(default_factory=dict)
    snmp_info: Dict[str, Any] = field(default_factory=dict)
    smart_iot_info: Dict[str, Any] = field(default_factory=dict)
    ssh_info: Dict[str, Any] = field(default_factory=dict)
    smb_info: Dict[str, Any] = field(default_factory=dict)
    dns_info: Dict[str, Any] = field(default_factory=dict)
    extended_iot_info: Dict[str, Any] = field(default_factory=dict)
    netbios_name: Optional[str] = None
    netbios_group: Optional[str] = None

    # Forensics & Security
    fingerprint_reasons: List[str] = field(default_factory=list)
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    risk_score: int = 0  # 0 (Safe) to 100 (Critical)

    # User Customization (loaded from SQLite)
    custom_name: str = ""
    trust_state: str = "known"  # trusted, known, watchlist, intruder
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def synthesize_device_profile(
    ip: str,
    base_host: Dict[str, Any],
    mdns_list: List[Dict[str, Any]],
    upnp_data: Dict[str, Any],
    dhcp_hostname: Optional[str] = None,
) -> DeviceProfile:
    """
    Execute deep per-host active probes and synthesize all signals into a rich DeviceProfile.
    """
    now = time.time()
    mac = base_host.get("mac", "00:00:00:00:00:00").upper()
    is_local = bool(base_host.get("is_local", False))
    is_gateway = bool(base_host.get("is_gateway", False))
    mac_intel: MACIntelligence = oui_db.lookup(mac)

    profile = DeviceProfile(
        ip=ip,
        mac=mac_intel.mac,
        ipv6_addresses=base_host.get("ipv6_addresses", []),
        is_local=is_local,
        is_gateway=is_gateway,
        neigh_state=base_host.get("neigh_state", "REACHABLE"),
        vendor=mac_intel.vendor,
        vendor_address=mac_intel.vendor_address,
        oui_prefix=mac_intel.oui_prefix,
        registry_type=mac_intel.registry_type,
        is_randomized_mac=mac_intel.is_locally_administered,
        randomization_profile=mac_intel.randomization_profile,
        mdns_services=mdns_list,
        upnp_info=upnp_data,
        first_seen=now,
        last_seen=now,
    )

    reasons: List[str] = []
    confidence = 35

    if not mac_intel.is_locally_administered and "Unknown" not in mac_intel.vendor and "Unregistered" not in mac_intel.vendor:
        reasons.append(f"IEEE Hardware OUI {mac_intel.oui_prefix} registered to {mac_intel.vendor}")
        confidence += 15
    elif mac_intel.is_locally_administered:
        reasons.append(f"IEEE 802.11 Locally Administered Bit (U/L=1) set: {mac_intel.randomization_profile}")
        if mac_intel.unmasked_parent_vendor:
            reasons.append(
                f"IEEE LAA Virtual BSSID unmasked to parent OUI {mac_intel.unmasked_parent_oui} ({mac_intel.unmasked_parent_vendor})"
            )

    # Collect extra ports advertised by mDNS
    extra_ports = [svc["port"] for svc in mdns_list if svc.get("port", 0) > 0]

    # Run per-host deep probes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        fut_lat = ex.submit(measure_single_host_latency, ip, is_local)
        fut_ports = ex.submit(scan_ports_and_banners, ip, extra_ports)
        fut_nb = ex.submit(probe_netbios_and_rdns, ip)
        fut_ps = ex.submit(probe_playstation_ddp, ip)
        fut_snmp = ex.submit(probe_snmp_sysinfo, ip)
        fut_gw = ex.submit(probe_tmobile_gateway, ip) if is_gateway else None

        rtt_ms, rtt_method, ttl = fut_lat.result()
        port_services = fut_ports.result()
        rdns_host, nb_name, nb_group = fut_nb.result()
        ps_info = fut_ps.result()
        snmp_info = fut_snmp.result()
        gw_info = fut_gw.result() if fut_gw else None

    profile.rtt_ms = rtt_ms
    profile.rtt_method = rtt_method
    profile.ttl = ttl
    profile.port_services = port_services
    profile.open_ports = [p["port"] for p in port_services]
    profile.netbios_name = nb_name
    profile.netbios_group = nb_group

    # Conditional deep probes based on open ports / mDNS
    roku_info = None
    if 8060 in profile.open_ports or any("roku" in str(v).lower() for v in upnp_data.values()):
        roku_info = probe_roku_ecp(ip)
    airplay_info = probe_airplay_bplist(ip, profile.open_ports)
    spotify_info = probe_spotify_connect(ip, mdns_list, profile.open_ports)
    cast_info = probe_google_cast_eureka(ip, profile.open_ports, mdns_list)
    hk_info = probe_homekit_and_matter(ip, profile.open_ports, mdns_list)
    smart_iot = probe_smart_iot_and_tv(ip, profile.open_ports)
    ssh_info = probe_ssh_kex_and_hostkeys(ip, 22) if 22 in profile.open_ports else None
    smb_info = probe_smb2_negotiate(ip, 445) if 445 in profile.open_ports else None
    dns_info = (
        probe_dns_security_posture(ip)
        if (is_gateway or 53 in profile.open_ports or 853 in profile.open_ports)
        else None
    )
    ext_iot = (
        probe_extended_iot_and_infra(ip, profile.open_ports)
        if any(p in profile.open_ports for p in (80, 1400, 1883, 2375, 11434, 32400))
        else {}
    )

    if roku_info:
        profile.roku_info = roku_info
    if airplay_info:
        profile.airplay_info = airplay_info
        disp_sum = airplay_info.get("display_summary")
        hw_rev = airplay_info.get("hardwareRevision")
        b_date = airplay_info.get("firmwareBuildDate")
        if disp_sum:
            reasons.append(
                f"Apple AirPlay Binary Plist (:7000/info) decoded: Display {disp_sum}, "
                f"HW Rev {hw_rev or 'N/A'}, Build {b_date or 'N/A'}, SDK {airplay_info.get('sdk', '')}"
            )
    if spotify_info:
        profile.spotify_info = spotify_info
    if ps_info:
        profile.playstation_info = ps_info
    if gw_info:
        profile.gateway_5g_info = gw_info
    if cast_info:
        profile.google_cast_info = cast_info
        reasons.append(f"Google Cast / Eureka Protocol decoded: {cast_info.get('friendly_name', '')} ({cast_info.get('model', '')})")
    if hk_info:
        profile.homekit_matter_info = hk_info
        reasons.append(f"{hk_info.get('ecosystem', 'HomeKit/Matter')} decoded: {hk_info.get('model', '')} ({hk_info.get('category_name', '')})")
    if snmp_info:
        profile.snmp_info = snmp_info
        reasons.append(f"SNMPv2c MIB-II sysDescr: {snmp_info.get('sysDescr', '')[:80]}")
    if smart_iot:
        profile.smart_iot_info = smart_iot
        reasons.append(f"Smart IoT / TV LAN Protocol ({smart_iot.get('protocol')}): {smart_iot.get('model', '')}")
    if ssh_info:
        profile.ssh_info = ssh_info
        reasons.append(
            f"SSHv2 KEXINIT decoded: HASSH {ssh_info.get('hassh_server')} • Grade {ssh_info.get('crypto_grade')}"
        )
    if smb_info:
        profile.smb_info = smb_info
        reasons.append(
            f"SMB2/3 Negotiate decoded: {smb_info.get('dialect')} • Signing Required={smb_info.get('signing_required')}"
        )
    if dns_info and (dns_info.get("dns_active") or dns_info.get("dot_port_853_open")):
        profile.dns_info = dns_info
        reasons.append(
            f"DNS Resolver Audit (:53/:853): {dns_info.get('security_grade')} • DNSSEC AD={dns_info.get('dnssec_validated')}"
        )
    if ext_iot:
        profile.extended_iot_info = ext_iot
        for proto_k, proto_v in ext_iot.items():
            if isinstance(proto_v, dict):
                reasons.append(
                    f"Extended IoT/Infra Prober ({proto_v.get('protocol', proto_k)}): "
                    f"{proto_v.get('model') or proto_v.get('room_name') or proto_v.get('version') or 'Active'}"
                )

    # OS family inference from TTL: normalize to 64/128/255 initial TTL
    # (observed TTL decrements per hop; 63→64, 127→128, 254→255).
    if ttl is not None:
        if ttl <= 64:
            profile.os_family = "Linux / Embedded / UNIX (TTL=64)"
        elif ttl <= 128:
            profile.os_family = "Windows NT Stack (TTL=128)"
        else:
            profile.os_family = "Network Appliance / BSD (TTL=255)"

    # Hostname resolution priority: mDNS -> DHCP -> NetBIOS -> Reverse DNS -> Local
    for svc in mdns_list:
        h = svc.get("hostname", "")
        if h and h != "none.local":
            profile.hostname = h
            break
    if not profile.hostname and dhcp_hostname:
        profile.hostname = dhcp_hostname
    if not profile.hostname and nb_name:
        profile.hostname = nb_name
    if not profile.hostname and rdns_host:
        profile.hostname = rdns_host
    if is_local and not profile.hostname:
        profile.hostname = f"{socket.gethostname()}.local"

    # =========================================================================
    # MULTI-SIGNAL CLASSIFICATION CASCADE
    # =========================================================================

    # 1. Local Host (This Machine)
    if is_local:
        uname = socket.gethostname()
        profile.brand = "Intel / Linux Workstation"
        profile.model = "Ubuntu Linux 7.0 Kernel (Sovereign Scanner Node)"
        profile.display_name = f"{uname} (This Workstation)"
        profile.category = "Workstation / Scanner Host"
        profile.icon_type = "laptop"
        profile.os_family = "Ubuntu Linux x86_64 (Kernel 7.0.0-38-generic)"
        profile.power_state = "ACTIVE (Local Host)"
        confidence = 100
        reasons.append("Local network interface hardware binding on primary scanner host")

    # 2. Network Gateway / Router
    elif is_gateway:
        if gw_info and "device" in gw_info:
            dev = gw_info.get("device", {})
            sig5g = gw_info.get("signal", {}).get("5g", {})
            tm_time = gw_info.get("time", {})
            profile.brand = dev.get("manufacturer", "Arcadyan")
            profile.model = f"T-Mobile {dev.get('model', 'TMO-G4AR')} ({dev.get('friendlyName', '5G Gateway')})"
            profile.model_number = dev.get("model", "TMO-G4AR")
            profile.serial_number = dev.get("serial", "")
            profile.firmware_version = f"v{dev.get('softwareVersion', '')} (HW {dev.get('hardwareVersion', '')})"
            profile.display_name = f"T-Mobile {dev.get('friendlyName', '5G Gateway')} ({dev.get('model', 'TMO-G4AR')})"
            profile.category = "5G NR Cellular Gateway / Router"
            profile.icon_type = "router"
            profile.os_family = "OpenWrt / Linux Embedded (lighttpd/1.4.78)"
            profile.uptime_seconds = tm_time.get("upTime")
            profile.power_state = f"ACTIVE (5G Band {', '.join(sig5g.get('bands', ['n41']))} • SINR {sig5g.get('sinr', '?')} dB)"
            confidence = 100
            reasons.append(
                f"Authenticated TMI v1 Gateway Telemetry: {profile.brand} {profile.model_number}, "
                f"Serial {profile.serial_number}, FW {profile.firmware_version}, 5G gNBID {sig5g.get('gNBID')}"
            )
        else:
            upnp_mfg = upnp_data.get("manufacturer", "")
            upnp_model = upnp_data.get("modelName", "")
            upnp_fn = upnp_data.get("friendlyName", "")
            brand_guess = upnp_mfg or (profile.vendor if "Unknown" not in profile.vendor else "Subnet")
            model_guess = upnp_model or f"{brand_guess} Default Gateway Router"
            profile.brand = brand_guess
            profile.model = model_guess
            profile.display_name = upnp_fn or f"{brand_guess} Gateway ({ip})"
            profile.category = "Network Gateway / Router"
            profile.icon_type = "router"
            profile.power_state = "ACTIVE (Subnet Gateway)"
            confidence = 85
            reasons.append(f"Designated primary IPv4 default gateway for subnet via {profile.mac}")
            if upnp_fn:
                reasons.append(f"UPnP Gateway Device Descriptor: {upnp_fn} ({upnp_model})")

    # 3. Roku OS TV or Roku Streaming Stick (via Roku ECP :8060)
    elif roku_info:
        is_tv = roku_info.get("is-tv", "").lower() == "true"
        vendor_name = roku_info.get("vendor-name", upnp_data.get("manufacturer", "Roku"))
        model_name = roku_info.get("model-name", upnp_data.get("modelName", "Roku Device"))
        model_num = roku_info.get("model-number", upnp_data.get("modelNumber", ""))
        friendly = (
            roku_info.get("user-device-name")
            or roku_info.get("friendly-device-name")
            or upnp_data.get("friendlyName")
            or model_name
        )
        screen_sz = roku_info.get("screen-size", "")
        res = roku_info.get("ui-resolution", "")
        sw_ver = roku_info.get("software-version", "")
        sw_build = roku_info.get("software-build", "")
        pwr_mode = roku_info.get("power-mode", "PowerOn")
        active_app = roku_info.get("active_app", "")

        profile.brand = vendor_name
        if is_tv and screen_sz:
            profile.model = f'{vendor_name} {screen_sz}" {model_name} Roku TV ({model_num})'
            profile.category = "Smart TV / QLED Display"
            profile.icon_type = "tv"
        else:
            profile.model = f"{vendor_name} {model_name} ({model_num})"
            profile.category = "Streaming Media Player"
            profile.icon_type = "stick"

        profile.model_number = model_num
        profile.serial_number = roku_info.get("serial-number", upnp_data.get("serialNumber", ""))
        profile.udn = roku_info.get("udn", upnp_data.get("UDN", ""))
        profile.display_name = f"{friendly} ({profile.model})" if friendly not in profile.model else profile.model
        profile.os_family = f"Roku OS {sw_ver} (Linux)" if sw_ver else "Roku OS / Linux"
        profile.firmware_version = f"Roku OS {sw_ver} (Build {sw_build})" if sw_ver else ""
        profile.active_app = active_app
        profile.hardware_image_url = f"/api/device-image/{ip}"

        # Check mDNS AirPlay firmware if Roku ECP didn't include software-version
        if not profile.firmware_version:
            for svc in mdns_list:
                fv = svc.get("txt", {}).get("fv")
                if fv:
                    profile.firmware_version = fv
                    break

        eth_mac = roku_info.get("ethernet-mac", "").upper()
        if eth_mac and eth_mac != profile.mac and eth_mac != "00:00:00:00:00:00":
            profile.secondary_macs.append(eth_mac)

        if roku_info.get("uptime", "").isdigit():
            profile.uptime_seconds = int(roku_info["uptime"])

        if "poweron" in pwr_mode.lower():
            profile.power_state = f"ACTIVE ({active_app})" if active_app else "ACTIVE (Screen On)"
        else:
            profile.power_state = f"STANDBY ({pwr_mode})"

        confidence = 99
        reasons.append(
            f"Roku ECP (/query/device-info) + UPnP XML verified: {profile.model}, "
            f"SN {profile.serial_number}, UI {res}, Wi-Fi Driver {roku_info.get('wifi-driver', 'realtek')}"
        )

    # 4. Sony PlayStation 4 / PlayStation 5 (via PlayStation DDP UDP 987/9302 or Spotify Connect)
    elif ps_info:
        htype = ps_info.get("host-type", "PS5").upper()
        hname = ps_info.get("host-name", htype)
        hid = ps_info.get("host-id", "")
        fw_fmt = ps_info.get("firmware_formatted", ps_info.get("system-version", ""))
        pwr = ps_info.get("power_state", "ACTIVE")

        profile.brand = "Sony Interactive Entertainment"
        profile.model = f"Sony PlayStation 5 ({hname})" if htype == "PS5" else f"Sony PlayStation 4 ({hname})"
        profile.model_number = htype
        profile.serial_number = hid
        profile.display_name = f"{hname} — Sony {'PlayStation 5' if htype == 'PS5' else 'PlayStation 4'}"
        profile.category = "Game Console"
        profile.icon_type = "console"
        profile.os_family = f"Orbis OS / FreeBSD ({htype} System Software)"
        profile.firmware_version = f"System Software v{fw_fmt}" if fw_fmt else ""
        profile.power_state = pwr

        if len(hid) == 12:
            primary_mac = ":".join(hid[i : i + 2] for i in range(0, 12, 2)).upper()
            if primary_mac != profile.mac:
                profile.secondary_macs.append(primary_mac)

        confidence = 99
        reasons.append(
            f"Sony PlayStation DDP (UDP :{ps_info.get('ddp_port')}) response: {ps_info.get('status_line')}, "
            f"Host-Type={htype}, Host-Name={hname}, Host-ID={hid}, Firmware={fw_fmt}"
        )
        if spotify_info:
            reasons.append(
                f"Spotify Connect (:41800/spConn) confirmed deviceType={spotify_info.get('deviceType')} "
                f"modelDisplayName={spotify_info.get('modelDisplayName')}"
            )

    # 5. Smart Speaker / Voice Assistant / Spotify Connect Device (e.g. Amazon Echo Dot)
    elif spotify_info:
        brand_raw = spotify_info.get("brandDisplayName", profile.vendor)
        model_raw = spotify_info.get("modelDisplayName", "Smart Speaker").replace("_", " ")
        dev_type = spotify_info.get("deviceType", "SPEAKER").upper()
        aliases = spotify_info.get("aliases", [])
        alias_name = aliases[0].get("name", "") if aliases and isinstance(aliases[0], dict) else ""
        remote_name = spotify_info.get("remoteName") or alias_name or model_raw
        lib_ver = spotify_info.get("libraryVersion", "")

        profile.brand = brand_raw.title() if brand_raw.islower() else brand_raw
        profile.model = f"{profile.brand} {model_raw}"
        profile.model_number = model_raw
        profile.serial_number = spotify_info.get("deviceID", "")[:24]
        profile.display_name = f"{remote_name} ({profile.model})" if remote_name != profile.model else profile.model
        profile.firmware_version = f"Spotify SDK {lib_ver} (v{spotify_info.get('version', '')})" if lib_ver else ""
        profile.os_family = "Fire OS / Linux Embedded" if "amazon" in profile.brand.lower() else "Embedded Audio OS"
        profile.power_state = "ACTIVE (Spotify ZeroConf Ready)"

        if dev_type == "SPEAKER":
            profile.category = "Smart Speaker / Voice Assistant"
            profile.icon_type = "speaker"
        elif dev_type == "GAMECONSOLE":
            profile.category = "Game Console"
            profile.icon_type = "console"
        elif dev_type == "TV":
            profile.category = "Smart TV"
            profile.icon_type = "tv"
        else:
            profile.category = "Smart Media Device"
            profile.icon_type = "speaker"

        confidence = 98
        reasons.append(
            f"Spotify ZeroConf ({spotify_info.get('endpoint_url')}) verified: "
            f"brand={brand_raw}, model={model_raw}, alias='{remote_name}', type={dev_type}"
        )

    # 5b. Google Cast / Chromecast / Nest Hub / Android TV
    elif cast_info and (cast_info.get("model") or cast_info.get("friendly_name")):
        c_model = cast_info.get("model", "Google Cast Device")
        c_fn = cast_info.get("friendly_name", c_model)
        c_app = cast_info.get("active_app", "")
        profile.brand = cast_info.get("manufacturer", "Google")
        profile.model = c_model
        profile.display_name = f"{c_fn} ({c_model})" if c_fn != c_model else c_model
        profile.firmware_version = cast_info.get("firmware", "")
        profile.active_app = c_app
        profile.power_state = f"ACTIVE ({c_app})" if c_app else "ACTIVE (Google Cast Ready)"
        profile.category = "Smart Display / Google Cast" if "hub" in c_model.lower() or "tv" in c_model.lower() else "Smart Speaker / Google Cast"
        profile.icon_type = "tv" if "tv" in c_model.lower() else "speaker"
        confidence = 98

    # 5c. Apple HomeKit (HAP) or Matter / Thread Smart Home Endpoint
    elif hk_info and (hk_info.get("model") or hk_info.get("ecosystem")):
        hk_model = hk_info.get("model", hk_info.get("ecosystem", "Smart Home Accessory"))
        hk_cat = hk_info.get("category_name", "Smart Home / IoT Appliance")
        profile.brand = profile.vendor if "Unknown" not in profile.vendor else "Apple HomeKit / Matter"
        profile.model = hk_model
        profile.display_name = f"{hk_model} ({hk_cat})"
        profile.category = hk_cat
        profile.icon_type = "iot"
        profile.power_state = f"ACTIVE ({hk_info.get('pairing_status', 'HomeKit/Matter')})"
        confidence = 96

    # 5d. Smart IoT Relay / Plug (TP-Link Kasa, Shelly) or Samsung Tizen Smart TV
    elif smart_iot and smart_iot.get("model"):
        s_proto = smart_iot.get("protocol", "iot")
        s_model = smart_iot.get("model", "Smart Device")
        s_alias = smart_iot.get("alias") or smart_iot.get("friendly_name") or s_model
        profile.brand = "TP-Link Kasa" if s_proto == "kasa" else ("Shelly" if s_proto == "shelly" else "Samsung")
        profile.model = s_model
        profile.display_name = f"{s_alias} ({s_model})" if s_alias != s_model else s_model
        profile.firmware_version = smart_iot.get("sw_ver") or smart_iot.get("firmware") or ""
        profile.category = "Smart TV / Tizen Display" if s_proto == "samsung_tizen" else "Smart Plug / Power Relay"
        profile.icon_type = "tv" if s_proto == "samsung_tizen" else "iot"
        if smart_iot.get("relay_state"):
            profile.power_state = f"ACTIVE (Relay {smart_iot['relay_state']})"
        confidence = 97

    # 5e. Enterprise SNMPv2c Network Switch / NAS / Appliance
    elif snmp_info and (snmp_info.get("sysDescr") or snmp_info.get("sysName")):
        sys_n = snmp_info.get("sysName") or profile.hostname or ip
        sys_d = snmp_info.get("sysDescr", "SNMP Managed Appliance")
        profile.brand = profile.vendor
        profile.model = sys_d[:64]
        profile.display_name = f"{sys_n} ({sys_d[:40]})"
        profile.category = "Managed Switch / SNMP Infrastructure"
        profile.icon_type = "router"
        confidence = 97

    # 5f. Sonos ZonePlayer Multi-Room Smart Speaker (:1400)
    elif ext_iot.get("sonos"):
        sonos = ext_iot["sonos"]
        # Accept both camelCase (UPnP XML tags as produced by probers.py:2284) and snake_case
        room = (
            sonos.get("roomName")
            or sonos.get("displayName")
            or sonos.get("room_name")
            or sonos.get("friendly_name")
            or "Sonos Speaker"
        )
        s_mod = sonos.get("modelName") or sonos.get("model") or "Sonos ZonePlayer"
        model_number = sonos.get("modelNumber") or sonos.get("model_number") or ""
        serial = sonos.get("serialNum") or sonos.get("serial_num") or ""
        software = sonos.get("softwareVersion") or sonos.get("software_version") or ""
        hardware = sonos.get("hardwareVersion") or sonos.get("hardware_version") or ""
        profile.brand = "Sonos"
        profile.model = f"Sonos {s_mod} ({model_number})".strip()
        profile.model_number = model_number
        profile.serial_number = serial
        profile.firmware_version = f"Sonos OS {software} (HW {hardware})"
        profile.display_name = f"{room} ({s_mod})"
        profile.category = "Smart Speaker / Multi-Room Audio"
        profile.icon_type = "speaker"
        profile.power_state = "ACTIVE (Sonos UPnP AVTransport Ready)"
        confidence = 99

    # 5g. Philips Hue / Signify Zigbee Smart Lighting Bridge (:80/api/config)
    elif ext_iot.get("philips_hue"):
        hue = ext_iot["philips_hue"]
        h_name = hue.get("name") or hue.get("bridge_name") or "Philips Hue Bridge"
        h_mod = hue.get("modelid") or hue.get("model_id") or "BSB002"
        h_bridge = hue.get("bridgeid") or hue.get("bridge_id") or ""
        profile.brand = "Signify / Philips Hue"
        profile.model = f"Philips Hue Zigbee Bridge ({h_mod})"
        profile.model_number = h_mod
        profile.serial_number = h_bridge
        profile.firmware_version = f"SW {hue.get('swversion', '')} (API v{hue.get('apiversion', '')})"
        profile.display_name = f"{h_name} ({h_mod})"
        profile.category = "Zigbee Smart Lighting Bridge"
        profile.icon_type = "iot"
        profile.power_state = "ACTIVE (Zigbee Coordinator Online)"
        confidence = 99

    # 5h. Ollama Local AI / LLM Inference Server (:11434)
    elif ext_iot.get("ollama_ai") or ext_iot.get("ollama"):
        oll = ext_iot.get("ollama_ai") or ext_iot.get("ollama")
        models = oll.get("models") or oll.get("installed_models") or []
        profile.brand = profile.vendor if "Unknown" not in profile.vendor else "Ollama AI Node"
        profile.model = f"Ollama LLM Inference Host ({oll.get('model_count', 0)} Models)"
        profile.display_name = f"Ollama AI Server ({ip}) — {', '.join(models[:2]) or 'Ready'}"
        profile.category = "AI / LLM Inference Server"
        profile.icon_type = "server"
        profile.power_state = f"ACTIVE ({oll.get('model_count', 0)} Local LLMs Loaded)"
        confidence = 98

    # 5i. Plex Media Server (:32400/identity)
    elif ext_iot.get("plex"):
        plx = ext_iot["plex"]
        profile.brand = profile.vendor if "Unknown" not in profile.vendor else "Plex Media Server"
        profile.model = f"Plex Media Server v{plx.get('version', '')}"
        profile.serial_number = (plx.get("machine_identifier") or plx.get("machine_id") or "")[:24]
        profile.firmware_version = plx.get("version", "")
        profile.display_name = f"Plex Media Server ({ip} • v{plx.get('version', '')})"
        profile.category = "Media Streaming Server"
        profile.icon_type = "server"
        profile.power_state = "ACTIVE (Plex Transcoder Ready)"
        confidence = 98

    # 6. Generic UPnP Device (if not Roku)
    elif upnp_data and upnp_data.get("friendlyName"):
        fn = upnp_data.get("friendlyName", "")
        manuf = upnp_data.get("manufacturer", profile.vendor)
        mname = upnp_data.get("modelName", "")
        mnum = upnp_data.get("modelNumber", "")
        profile.brand = manuf
        profile.model = f"{manuf} {mname} {mnum}".strip()
        profile.model_number = mnum
        profile.serial_number = upnp_data.get("serialNumber", "")
        profile.udn = upnp_data.get("UDN", "")
        profile.display_name = f"{fn} ({profile.model})" if fn not in profile.model else profile.model
        profile.category = "UPnP Smart Device"
        profile.icon_type = "iot"
        confidence = 90
        reasons.append(f"UPnP Device Descriptor ({upnp_data.get('location')}): {profile.display_name}")

    # 7. Amazon OUI Stealth IoT / Fire / Echo / Blink / Smart Home Client
    elif "amazon" in profile.vendor.lower():
        profile.brand = "Amazon"
        profile.model = "Amazon Smart Home / Fire OS / Echo IoT Client"
        profile.display_name = f"Amazon IoT / Fire Device ({profile.mac[-8:]})"
        profile.category = "Smart Home / IoT Appliance"
        profile.icon_type = "iot"
        profile.os_family = "Fire OS / Amazon FreeRTOS (TTL=64)"
        profile.power_state = "ACTIVE (Stealth Client Mode)"
        confidence = 84
        reasons.append(
            f"Amazon Technologies Inc. Hardware OUI ({profile.oui_prefix}) + Linux/FreeRTOS TTL=64 + "
            "Zero Open TCP Ports (Characteristic of Amazon Smart Plug / Fire Tablet / Blink / Ring Chime)"
        )

    # 8. Nintendo Switch / Console OUI (including Mitsumi Nintendo wireless modules)
    elif "nintendo" in profile.vendor.lower() or "mitsumi" in profile.vendor.lower():
        profile.brand = "Nintendo"
        is_mitsumi = "mitsumi" in profile.vendor.lower()
        profile.model = "Nintendo Handheld / Switch Wireless Console" if is_mitsumi else "Nintendo Switch Console"
        profile.display_name = f"Nintendo Console ({profile.mac[-8:]})" if is_mitsumi else f"Nintendo Switch ({profile.mac[-8:]})"
        profile.category = "Game Console"
        profile.icon_type = "console"
        profile.os_family = "Nintendo Horizon OS"
        confidence = 92
        reasons.append(f"Nintendo / Mitsumi Hardware OUI ({profile.oui_prefix}: {profile.vendor})")

    # 9. Locally Administered Privacy MAC (Smartphone / Tablet with iOS 14+ / Android 10+ Private Wi-Fi Address)
    elif profile.is_randomized_mac:
        eui_unmasked = unmask_eui64_ipv6_mac(profile.ipv6_addresses)
        if eui_unmasked:
            real_mac, real_intel = eui_unmasked
            if real_mac not in profile.secondary_macs:
                profile.secondary_macs.append(real_mac)
            reasons.append(
                f"SLAAC IPv6 EUI-64 de-anonymized burned-in MAC {real_mac} ({real_intel.vendor})"
            )
            profile.brand = real_intel.vendor
        else:
            profile.brand = "Apple iOS / Google Android"
        profile.model = "Mobile Handset (Private Wi-Fi MAC Enabled)"
        profile.display_name = f"Mobile Smartphone / Tablet ({profile.mac[:8]}…)"
        profile.category = "Smartphone / Mobile Handset"
        profile.icon_type = "phone"
        profile.os_family = "iOS 14+ / Android 10+ (802.11 Privacy MAC)"
        if rtt_ms and rtt_ms > 90:
            profile.power_state = f"POWERSAVE IDLE (802.11 DTIM ~{int(rtt_ms)}ms)"
            reasons.append(
                f"TCP SYN-RST latency ({rtt_ms} ms) matches 802.11 DTIM Beacon Power-Save polling interval "
                "typical of a sleeping iPhone / Android handset with screen locked"
            )
        else:
            profile.power_state = "ACTIVE (Screen Awake)"
        if "ICMP" not in rtt_method:
            reasons.append("Drops unsolicited ICMP Echo requests while responding with TCP RST on closed ports")
        confidence = 86

    # 10. Linux / Windows / Server / Workstation identified via Open Ports & Service Banners
    elif profile.open_ports:
        banners_concat = " ".join(
            f"{ps.get('server', '')} {ps.get('banner', '')} {ps.get('http_title', '')}"
            for ps in profile.port_services
        )
        http_title = next((ps.get("http_title", "").strip() for ps in profile.port_services if ps.get("http_title")), "")
        ssh_banner = next((ps.get("banner", "").strip() for ps in profile.port_services if ps.get("port") == 22 and ps.get("banner")), "")
        if "ubuntu" in banners_concat.lower() or "debian" in banners_concat.lower():
            srv_hdr = next((ps.get("server") for ps in profile.port_services if ps.get("server")), "Ubuntu Server")
            profile.brand = "Canonical Ubuntu / Linux"
            profile.model = f"Ubuntu Linux Host ({ssh_banner or srv_hdr})"
            if http_title:
                profile.active_app = http_title
                profile.power_state = f"ACTIVE ({http_title})"
                profile.display_name = f"{http_title} ({ip} • Ubuntu Linux)"
            else:
                profile.display_name = f"Ubuntu Linux Host ({ip}) — {srv_hdr}"
            profile.category = "Linux Server / Workstation"
            profile.icon_type = "server"
            profile.os_family = f"Ubuntu Linux ({ssh_banner or srv_hdr})"
            confidence = 97 if http_title else 95
            reasons.append(
                f"HTTP/SSH Banner fingerprinted OS & Application Stack: {http_title or srv_hdr} ({ssh_banner or srv_hdr}) on ports {profile.open_ports}"
            )
        elif 3389 in profile.open_ports or 445 in profile.open_ports or 22 in profile.open_ports:
            profile.brand = profile.vendor
            profile.model = f"Workstation / Server ({', '.join(str(p) for p in profile.open_ports)})"
            profile.display_name = http_title or profile.hostname or f"Workstation / Server ({ip})"
            if http_title:
                profile.active_app = http_title
                profile.power_state = f"ACTIVE ({http_title})"
            profile.category = "Server / Workstation"
            profile.icon_type = "server"
            confidence = 85
            reasons.append(f"Server/Workstation management ports active: {profile.open_ports}")
        else:
            profile.brand = profile.vendor
            profile.model = f"{profile.vendor} Network Host"
            profile.display_name = profile.hostname or f"{profile.vendor} ({ip})"
            profile.category = "Network Endpoint"
            profile.icon_type = "device"
            confidence = 75

    # 11. Default fallback
    else:
        profile.brand = profile.vendor
        profile.model = f"{profile.vendor} Network Device"
        profile.display_name = profile.hostname or f"{profile.vendor} ({ip})"
        profile.category = "Network Endpoint"
        profile.icon_type = "device"

    # =========================================================================
    # SECURITY POSTURE & VULNERABILITY AUDIT
    # =========================================================================
    findings: List[SecurityFinding] = []
    risk = 0

    if profile.is_gateway and 80 in profile.open_ports and 443 not in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="MEDIUM",
                title="Unencrypted HTTP Gateway Management & Telemetry API",
                description=(
                    f"Gateway at {ip}:80 exposes unencrypted HTTP management and unauthenticated "
                    "JSON hardware/cellular telemetry at /TMI/v1/gateway?get=all."
                ),
                remediation="Restrict gateway administration to trusted LAN VLANs and enforce strong admin passwords.",
            )
        )
        risk += 25

    if 8060 in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="LOW",
                title="Unauthenticated Roku External Control Protocol (ECP :8060)",
                description=(
                    f"Host {ip} exposes Roku ECP on TCP 8060 without authentication, allowing any LAN client "
                    "to query active apps, device serial numbers, or inject remote control keypresses."
                ),
                remediation="Set 'Control by mobile apps -> Network access' to 'Permissive/Disabled' in Roku Settings if not needed.",
            )
        )
        risk += 15

    if 23 in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title="Cleartext Telnet Service Exposed (TCP 23)",
                description="Telnet transmits credentials and session traffic in cleartext over the network.",
                remediation="Disable Telnet immediately and migrate to SSH (TCP 22) with key-based authentication.",
            )
        )
        risk += 60

    if 5555 in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title="Android Debug Bridge (ADB TCP 5555) Exposed Over Network",
                description="Network-exposed ADB allows arbitrary shell execution on the target device.",
                remediation="Disable Wireless Debugging / ADB over TCP in Developer Options.",
            )
        )
        risk += 65

    if 445 in profile.open_ports or 139 in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="MEDIUM",
                title="SMB / CIFS File Sharing Exposed",
                description=f"Host {ip} has SMB file sharing ports open on the local subnet.",
                remediation="Ensure SMBv1 is disabled, SMB signing is required, and guest access is turned off.",
            )
        )
        risk += 25

    if profile.is_randomized_mac:
        findings.append(
            SecurityFinding(
                severity="INFO",
                title="IEEE 802.11 Randomized Privacy MAC Active",
                description=(
                    f"MAC {profile.mac} has the Locally Administered bit set (0x{profile.mac[:2]}). "
                    "Device masks its factory IEEE OUI using per-SSID MAC randomization."
                ),
                remediation="Verify whether this mobile device belongs to an authorized household member or guest.",
            )
        )
        risk += 10

    if 7547 in profile.open_ports:
        findings.append(
            SecurityFinding(
                severity="MEDIUM",
                title="TR-069 / CWMP Carrier Provisioning Port Open (TCP 7547)",
                description=(
                    f"Gateway {ip} exposes TCP 7547 (CPE WAN Management Protocol) on the local interface."
                ),
                remediation="Verify TR-069 ACS authentication and ensure TCP 7547 is firewalled from untrusted VLANs.",
            )
        )
        risk += 20

    if smb_info and smb_info.get("ntlm_relay_vulnerable"):
        findings.append(
            SecurityFinding(
                severity="HIGH",
                title=f"SMB Packet Signing Not Required ({smb_info.get('dialect', 'SMB2/3')})",
                description=(
                    f"Host {ip}:445 negotiated {smb_info.get('dialect')} with Packet Signing "
                    f"{'Enabled' if smb_info.get('signing_enabled') else 'Disabled'} but Not Required, "
                    "making it vulnerable to Responder / NTLM Relay MITM attacks."
                ),
                remediation="Enable 'Microsoft network server: Digitally sign communications (always)' via GPO or set 'server signing = mandatory' in smb.conf.",
            )
        )
        risk += 35

    if ssh_info and (ssh_info.get("weak_kex") or ssh_info.get("weak_ciphers")):
        weak_items = (ssh_info.get("weak_kex") or []) + (ssh_info.get("weak_ciphers") or [])
        findings.append(
            SecurityFinding(
                severity="MEDIUM",
                title="Legacy SSHv2 Key Exchange or CBC Ciphers Enabled (:22)",
                description=(
                    f"SSH daemon on {ip}:22 advertises legacy cryptographic algorithms ({', '.join(weak_items[:4])}) "
                    f"with HASSH {ssh_info.get('hassh_server')}."
                ),
                remediation="Restrict KexAlgorithms to curve25519-sha256 / sntrup761x25519-sha512 and disable CBC/SHA-1 in sshd_config.",
            )
        )
        risk += 20

    if ext_iot.get("mqtt") and ext_iot["mqtt"].get("anonymous_allowed"):
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title="Unauthenticated Anonymous MQTT IoT Broker Exposed (TCP 1883)",
                description=(
                    f"MQTT broker at {ip}:1883 accepted an unauthenticated CONNECT packet (CONNACK 0x00), "
                    "allowing any LAN client to subscribe to `#` or inject smart-home actuator commands."
                ),
                remediation="Set `allow_anonymous false` in mosquitto.conf and enforce TLS + username/password ACLs.",
            )
        )
        risk += 55

    if ext_iot.get("docker_api"):
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title="Unauthenticated Docker Engine API Exposed (TCP 2375)",
                description=(
                    f"Host {ip}:2375 exposes the unencrypted Docker daemon REST socket "
                    f"(Docker v{ext_iot['docker_api'].get('version', '?')}), permitting instant root container breakout."
                ),
                remediation="Bind dockerd exclusively to unix:///var/run/docker.sock or enforce mutual TLS on TCP 2376.",
            )
        )
        risk += 85

    if dns_info and dns_info.get("version_bind_leak"):
        findings.append(
            SecurityFinding(
                severity="LOW",
                title="DNS Resolver Software Version Disclosed (CH TXT version.bind)",
                description=(
                    f"DNS server at {ip}:53 answered Chaos TXT version.bind with '{dns_info.get('version_bind_leak')}'."
                ),
                remediation="Hide version.bind in dnsmasq/named.conf (`version none;`) to prevent targeted fingerprinted exploits.",
            )
        )
        risk += 10

    for p_svc in profile.port_services:
        pt = p_svc.get("port")
        t_grade = p_svc.get("tls_grade", "")
        if t_grade.startswith("F"):
            findings.append(
                SecurityFinding(
                    severity="HIGH",
                    title=f"Deprecated TLS Protocol Version on TCP :{pt} ({p_svc.get('tls_version')})",
                    description=f"Service on {ip}:{pt} negotiated {p_svc.get('tls_version')} ({p_svc.get('tls_cipher')}).",
                    remediation="Disable TLSv1.0 and TLSv1.1; enforce TLSv1.2+ with AEAD cipher suites.",
                )
            )
            risk += 35

    if not findings:
        findings.append(
            SecurityFinding(
                severity="INFO",
                title="Hardened / Minimal Attack Surface",
                description=f"No high-risk unencrypted admin services or vulnerable ports detected on {ip}.",
                remediation="Continue monitoring for unexpected port or MAC changes.",
            )
        )

    # =========================================================================
    # DEEP HARDWARE & ENGINEERING DOSSIER + CONTROL CAPABILITY MATRIX
    # =========================================================================
    specs: Dict[str, str] = {
        "IPv4 Address": profile.ip,
        "Primary Hardware MAC": profile.mac,
        "IEEE OUI Manufacturer": f"{profile.vendor} ({profile.oui_prefix or 'LAA'})",
        "Registry Classification": profile.registry_type,
        "Kernel Neighbor State": profile.neigh_state,
        "OS / Network Stack": profile.os_family,
    }
    if profile.vendor_address:
        specs["Manufacturer HQ"] = profile.vendor_address
    if profile.secondary_macs:
        specs["Secondary / Bridged MACs"] = ", ".join(profile.secondary_macs)
    if profile.ipv6_addresses:
        specs["IPv6 Addresses"] = ", ".join(profile.ipv6_addresses)
    if profile.hostname:
        specs["Resolved Hostname"] = profile.hostname
    if profile.serial_number:
        specs["Serial / Hardware ID"] = profile.serial_number
    if profile.firmware_version:
        specs["Firmware / Build"] = profile.firmware_version
    if profile.ttl is not None:
        specs["IP Time-To-Live (TTL)"] = f"{profile.ttl} hops"

    controls: List[str] = ["ICMP / TCP Latency & Jitter Burst", "MTR Multi-Hop Path Trace", "Deep Nmap Service & Version Scan", "Custom Port Range & HTTP Probe", "IEEE 802 Wake-on-LAN (Magic Packet)"]

    if gw_info:
        g_dev = gw_info.get("device", {})
        g_sig = gw_info.get("signal", {}).get("5g", {})
        g_gen = gw_info.get("signal", {}).get("generic", {})
        specs["Gateway Model & Role"] = f"{g_dev.get('manufacturer', 'Arcadyan')} {g_dev.get('model', 'TMO-G4AR')} (HW {g_dev.get('hardwareVersion', 'R01')}, Role: {g_dev.get('role', 'gateway')})"
        specs["Base Manufacturer OUI"] = g_dev.get("manufacturerOUI", "001A2A")
        specs["5G NR Band & Tower"] = f"Band {', '.join(g_sig.get('bands', ['n41']))} • gNBID {g_sig.get('gNBID', '?')} • Cell ID {g_sig.get('cid', '?')}"
        specs["5G Cellular RF Metrics"] = f"RSRP {g_sig.get('rsrp')} dBm • SINR {g_sig.get('sinr')} dB • RSRQ {g_sig.get('rsrq')} dB • RSSI {g_sig.get('rssi')} dBm ({g_sig.get('bars')} Bars)"
        specs["Antenna & APN"] = f"{g_sig.get('antennaUsed', 'Internal_omni')} • APN {g_gen.get('apn', 'FBB.HOME')} • IPv6: {g_gen.get('hasIPv6')}"
        controls.insert(0, "T-Mobile 5G Gateway Telemetry & Admin Controller (/TMI/v1)")
        controls.insert(1, "Gateway DNS Resolver Benchmark (:53)")

    if roku_info:
        specs["Roku Device ID & UDN"] = f"{roku_info.get('device-id', 'N/A')} • UDN {roku_info.get('udn', 'N/A')}"
        specs["Advertising UUID"] = roku_info.get("advertising-id", "N/A")
        specs["UI & Panel Spec"] = (
            f"{roku_info.get('screen-size', '')}\" Panel (ID {roku_info.get('panel-id', 'N/A')}) • UI {roku_info.get('ui-resolution', '1080p')} • Tuner: {roku_info.get('tuner-type', 'None')}"
            if roku_info.get("screen-size")
            else f"UI Resolution: {roku_info.get('ui-resolution', '1080p')} • Stick Form Factor"
        )
        specs["Wireless Radio Driver"] = f"{roku_info.get('wifi-driver', 'realtek')} (5GHz Capable: {roku_info.get('has-wifi-5G-support', 'true')})"
        specs["System Build & GrandCentral"] = f"{roku_info.get('build-number', '')} • GrandCentral {roku_info.get('grandcentral-version', '')} • TRC {roku_info.get('trc-channel-version', '')}"
        specs["Audio & Captions"] = f"Closed Captions: {roku_info.get('closed-caption-mode', 'Off')} • Private Listening: {roku_info.get('supports-private-listening', 'false')} • Headphones: {roku_info.get('headphones-connected', 'false')}"
        specs["Power & ECP Security Mode"] = f"PowerMode: {roku_info.get('power-mode', 'PowerOn')} • ECP Setting Mode: {roku_info.get('ecp-setting-mode', 'default')} (TLS: {roku_info.get('ecp-tls-enabled', 'false')}) • Wake-on-WLAN: {roku_info.get('supports-wake-on-wlan', 'false')}"
        specs["Device Timezone"] = f"{roku_info.get('time-zone-tz', '')} (UTC{roku_info.get('time-zone-offset', '')}m)"
        if roku_info.get("active_app"):
            app_ver = f" v{roku_info['active_app_version']}" if roku_info.get("active_app_version") else ""
            app_id = f" [App ID {roku_info['active_app_id']}]" if roku_info.get("active_app_id") else ""
            specs["Foreground Application"] = f"{roku_info['active_app']}{app_ver}{app_id}"
        if roku_info.get("screensaver_name"):
            ss_ver = f" v{roku_info['screensaver_version']}" if roku_info.get("screensaver_version") else ""
            ss_id = f" [ID {roku_info['screensaver_id']}]" if roku_info.get("screensaver_id") else ""
            specs["Active Screensaver"] = f"{roku_info['screensaver_name']}{ss_ver}{ss_id}"
        if upnp_data and upnp_data.get("ssdp_wakeup"):
            specs["SSDP Wake-on-WLAN Header"] = upnp_data["ssdp_wakeup"]
        if upnp_data and upnp_data.get("ssdp_usns"):
            rtv = [u for u in upnp_data["ssdp_usns"] if "rtvaccel" in u]
            if rtv:
                specs["Roku RTV Accelerator USN"] = rtv[0]
        dial_list = roku_info.get("dial_apps", [])
        if dial_list:
            specs["Installed DIAL v2.1 Apps"] = ", ".join(f"{a['name']} ({a['state']})" for a in dial_list)
        controls.insert(0, "DIAL v2.1 App Launch, Deep-Link Payload & Process Termination")
        controls.insert(1, "Roku ECP Remote Control Keypresses (:8060)")

    if airplay_info:
        specs["AirPlay SDK & Device ID"] = f"{airplay_info.get('sdk', '')} • ID {airplay_info.get('deviceID', '')} (SourceVer {airplay_info.get('sourceVersion', '')})"
        specs["Hardware Board Revision"] = f"{airplay_info.get('hardwareRevision', 'N/A')} (FW Built {airplay_info.get('firmwareBuildDate', 'N/A')})"
        if airplay_info.get("display_summary"):
            specs["Physical EDID Display"] = airplay_info["display_summary"]
        pb = airplay_info.get("playbackCapabilities", {})
        if isinstance(pb, dict) and pb:
            specs["DRM & Web Engine"] = f"FairPlay {pb.get('fairPlayCDMPluginVersion', '')} • {pb.get('webEngineName', '')} {pb.get('webAppVersion', '')} (HLS.js {pb.get('hlsJSVersion', '')})"

    if ps_info:
        specs["PlayStation Host-Type & Name"] = f"{ps_info.get('host-type', '')} ({ps_info.get('host-name', '')})"
        specs["Burned-In Primary Host-ID"] = ps_info.get("host-id", "")
        specs["DDP Protocol & Request Port"] = f"DDP v{ps_info.get('device-discovery-protocol-version', '')} (UDP :{ps_info.get('ddp_port')}) • Host-Request :{ps_info.get('host-request-port', '997')}"
        specs["Console Power Status"] = f"{ps_info.get('power_state', '')} ({ps_info.get('status_line', '')})"
        controls.insert(0, "PlayStation DDP WAKEUP Packet + Dual-MAC Wake-on-LAN (UDP :987 / :9302)")

    if spotify_info:
        aliases = spotify_info.get("aliases", [])
        alias_str = ", ".join(a.get("name", "") for a in aliases if isinstance(a, dict))
        specs["Spotify Connect Identity"] = f"Brand: {spotify_info.get('brandDisplayName', '')} • Model: {spotify_info.get('modelDisplayName', '')} • Type: {spotify_info.get('deviceType', '')}"
        if alias_str or spotify_info.get("remoteName"):
            specs["Configured Speaker / Remote Name"] = alias_str or spotify_info.get("remoteName", "")
        specs["Spotify SDK & ZeroConf"] = f"API v{spotify_info.get('version', '')} • Lib {spotify_info.get('libraryVersion', 'Standard')} • AccountReq: {spotify_info.get('accountReq', 'PREMIUM')}"
        specs["Spotify Device UUID"] = spotify_info.get("deviceID", "")
        controls.insert(0, "Spotify ZeroConf Session Inspector & User Reset")

    for p_svc in profile.port_services:
        pt = p_svc.get("port")
        if p_svc.get("tls_grade"):
            specs[f"TLS Cryptographic Posture (:{pt})"] = (
                f"Grade {p_svc['tls_grade']} • {p_svc.get('tls_version', '')} • {p_svc.get('tls_cipher', '')}"
            )
        if p_svc.get("cert_subject"):
            specs[f"X.509 Cert Subject (:{pt})"] = p_svc["cert_subject"]
            specs[f"X.509 Cert Issuer & Serial (:{pt})"] = f"{p_svc.get('cert_issuer', '')} • Serial {p_svc.get('cert_serial', '')}"
            specs[f"X.509 Cert Validity / Epoch (:{pt})"] = f"{p_svc.get('cert_not_before', '')} -> {p_svc.get('cert_not_after', '')}"
            if p_svc.get("cert_sha256"):
                specs[f"X.509 Cert SHA-256 (:{pt})"] = p_svc["cert_sha256"]
        if p_svc.get("missing_security_headers"):
            specs[f"Missing HTTP Sec Headers (:{pt})"] = ", ".join(p_svc["missing_security_headers"])
        if p_svc.get("rp_version"):
            specs[f"PS Remote Play Daemon (:{pt})"] = f"RP-Version {p_svc['rp_version']} • Status 0x{p_svc.get('rp_reason', '')}"
        if pt == 7547:
            specs["TR-069 / CWMP Carrier Port"] = "TCP :7547 Active (CPE WAN Management Protocol)"

    if ssh_info:
        specs["SSH HASSH Server Fingerprint"] = ssh_info.get("hassh_server", "")
        specs["SSH Cryptographic Grade"] = ssh_info.get("crypto_grade", "")
        specs["SSH Key Exchange & HostKeys"] = (
            f"KEX: {', '.join(ssh_info.get('kex_algorithms', [])[:3])} • "
            f"HostKeys: {', '.join(ssh_info.get('host_key_algorithms', [])[:3])}"
        )
        controls.insert(0, "SSHv2 Cryptographic & HASSH Server Audit (:22)")

    if smb_info:
        specs["SMB Negotiated Dialect"] = smb_info.get("dialect", "")
        specs["SMB Packet Signing Posture"] = (
            "Required (Hardened)"
            if smb_info.get("signing_required")
            else ("Enabled but NOT Required (NTLM Relay Risk)" if smb_info.get("signing_enabled") else "Disabled")
        )
        if smb_info.get("server_guid"):
            specs["SMB Server GUID"] = smb_info["server_guid"]
        controls.insert(0, "SMB2/3 Dialect & NTLM-Relay Security Audit (:445)")

    if dns_info and (dns_info.get("dns_active") or dns_info.get("dot_port_853_open")):
        specs["DNS Resolver Posture (:53/:853)"] = (
            f"{dns_info.get('security_grade')} • DNSSEC AD={dns_info.get('dnssec_validated')} • "
            f"DoT 853={dns_info.get('dot_port_853_open')} • RTT {dns_info.get('query_rtt_ms')} ms"
        )
        if dns_info.get("version_bind_leak"):
            specs["DNS Chaos version.bind"] = dns_info["version_bind_leak"]
        controls.insert(0, "RFC 4035 DNSSEC & DoT (:853) Resolver Security Audit")

    if ext_iot.get("sonos"):
        sn = ext_iot["sonos"]
        specs["Sonos Room & ZonePlayer"] = f"{sn.get('roomName') or sn.get('room_name', '')} • {sn.get('modelName') or sn.get('model', '')} ({sn.get('modelNumber') or sn.get('model_number', '')})"
        sn_sw = sn.get("softwareVersion") or sn.get("software_version", "")
        sn_ser = sn.get("serialNum") or sn.get("serial_num", "")
        specs["Sonos Software & Serial"] = f"SW {sn_sw} • SN {sn_ser}"
        controls.insert(0, "Sonos UPnP AVTransport & Volume Controller (:1400)")

    if ext_iot.get("philips_hue"):
        hu = ext_iot["philips_hue"]
        specs["Philips Hue Bridge ID"] = f"{hu.get('bridgeid') or hu.get('bridge_id', '')} ({hu.get('modelid') or hu.get('model_id', '')})"
        specs["Hue Zigbee Firmware"] = f"SW {hu.get('swversion', '')} • API {hu.get('apiversion', '')}"

    if ext_iot.get("ollama_ai") or ext_iot.get("ollama"):
        ol = ext_iot.get("ollama_ai") or ext_iot.get("ollama")
        specs["Ollama Local LLMs (:11434)"] = ", ".join((ol.get("models") or ol.get("installed_models") or [])[:6]) or "0 models installed"

    if ext_iot.get("mqtt"):
        mq = ext_iot["mqtt"]
        mq_status = (
            "OPEN (Anonymous Unauthenticated Access)"
            if mq.get("anonymous_allowed")
            else f"Authenticated Broker (CONNACK 0x{mq.get('connack_code', 0):02x})"
        )
        specs["MQTT Broker (:1883)"] = f"{mq_status} (CONNACK 0x{mq.get('connack_code', 0):02x})"

    if profile.is_gateway:
        controls.insert(0, "UPnP IGD External NAT Port-Forwarding Audit")

    if any(p in profile.open_ports for p in (22, 80, 443, 1337, 3389, 8080)):
        controls.insert(0, "Native Desktop Client Launch (SSH / Web UI / RDP)")

    profile.hardware_specs = specs
    profile.control_capabilities = controls
    profile.security_findings = [asdict(f) for f in findings]
    profile.risk_score = min(100, risk)
    profile.confidence_score = min(100, confidence)
    profile.fingerprint_reasons = reasons

    return profile


def run_full_network_scan(
    net_info: NetworkInterfaceInfo,
    passive_hosts: Optional[Dict[str, str]] = None,
    dhcp_hostnames: Optional[Dict[str, str]] = None,
) -> List[DeviceProfile]:
    """
    Execute a full synchronized multi-vector scan of the active subnet:
    1. Kernel Layer-2 ARP + Neighbor Sweep
    2. Multicast mDNS / DNS-SD Service Harvest
    3. Multicast SSDP / UPnP / DIAL Harvest + XML Descriptor Fetch
    4. Per-Host Deep Protocol Probing & Heuristic Synthesis
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        fut_arp = ex.submit(arp_and_neighbor_sweep, net_info)
        fut_mdns = ex.submit(probe_mdns_services, net_info.interface)
        fut_ssdp = ex.submit(probe_ssdp_upnp, 1.5)

        arp_hosts = fut_arp.result()
        mdns_by_ip = fut_mdns.result()
        upnp_by_ip = fut_ssdp.result()

    # Re-harvest kernel neighbor table now that mDNS and SSDP have also completed
    arp_hosts.update(read_kernel_neighbors(net_info))

    # Merge any hosts discovered via mDNS, SSDP, or passive wire sniffer that weren't in ARP table yet
    if passive_hosts:
        for pip, pmac in passive_hosts.items():
            if pip not in arp_hosts and pip.startswith(net_info.ip.rsplit(".", 1)[0] + "."):
                arp_hosts[pip] = {
                    "ip": pip,
                    "mac": pmac.upper(),
                    "neigh_state": "PASSIVE_WIRE",
                    "is_local": pip == net_info.ip,
                    "is_gateway": pip == net_info.gateway_ip,
                    "ipv6_addresses": [],
                }

    for mip in list(mdns_by_ip.keys()) + list(upnp_by_ip.keys()):
        if mip not in arp_hosts and mip.startswith(net_info.ip.rsplit(".", 1)[0] + "."):
            arp_hosts[mip] = {
                "ip": mip,
                "mac": "00:00:00:00:00:00",
                "neigh_state": "MULTICAST_ONLY",
                "is_local": mip == net_info.ip,
                "is_gateway": mip == net_info.gateway_ip,
                "ipv6_addresses": [],
            }

    profiles: List[DeviceProfile] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        fut_to_ip = {}
        for ip, base_host in arp_hosts.items():
            mac_u = base_host.get("mac", "").upper()
            dhcp_h = dhcp_hostnames.get(mac_u) if dhcp_hostnames else None
            fut = ex.submit(
                synthesize_device_profile,
                ip,
                base_host,
                mdns_by_ip.get(ip, []),
                upnp_by_ip.get(ip, {}),
                dhcp_h,
            )
            fut_to_ip[fut] = ip

        for fut in concurrent.futures.as_completed(fut_to_ip):
            ip_failed = fut_to_ip[fut]
            try:
                profiles.append(fut.result())
            except Exception as exc:
                logger.warning("synthesize_device_profile failed for %s: %s", ip_failed, exc)

    # Sort by IP address numerically (with Gateway first)
    def _sort_key(p: DeviceProfile) -> Any:
        parts = [int(x) if x.isdigit() else 0 for x in p.ip.split(".")]
        return (0 if p.is_gateway else 1, parts)

    profiles.sort(key=_sort_key)
    return profiles


def audit_network_threats(
    devices: List[Dict[str, Any]],
    wifi_spectrum: Dict[str, Any],
    connected_ssid: str = "",
) -> List[Dict[str, str]]:
    """
    Correlate LAN neighbor tables and 802.11 RF spectrum to detect:
    1. ARP Cache Poisoning / Duplicate MAC MITM attacks
    2. Evil Twin Rogue Access Points spoofing the primary SSID
    3. High-power Close-Proximity Unencrypted / Camera APs (e.g. wifi-XXXX within 10m)
    4. High-risk exposed network services on the LAN
    """
    threats: List[Dict[str, str]] = []

    # 1. Check for duplicate MAC addresses across different IPs (ARP Spoofing / MITM)
    mac_to_ips: Dict[str, List[str]] = {}
    for d in devices:
        m = d.get("mac", "")
        ip = d.get("ip", "")
        if m and m != "00:00:00:00:00:00" and d.get("is_online"):
            mac_to_ips.setdefault(m, []).append(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            threats.append({
                "severity": "CRITICAL",
                "category": "ARP_SPOOFING_MITM",
                "title": f"Duplicate Hardware MAC Detected ({mac})",
                "details": f"Multiple IPv4 addresses ({', '.join(ips)}) resolve to the same Layer-2 MAC {mac}. Potential ARP cache poisoning / MITM.",
                "device_key": mac,
                "ip": ips[0],
                "mac": mac,
                "bssid": mac,
            })

    # 2. Check 802.11 Spectrum for Evil Twins & Close-Proximity Unencrypted Transmitters
    aps = wifi_spectrum.get("access_points", [])
    if connected_ssid:
        matching_aps = [a for a in aps if a.get("ssid") == connected_ssid]
        for a in matching_aps:
            sec = a.get("security", "")
            if "OPEN" in sec.upper():
                threats.append({
                    "severity": "CRITICAL",
                    "category": "EVIL_TWIN_AP",
                    "title": f"Unencrypted Evil Twin Broadcasting '{connected_ssid}' ({a.get('bssid')})",
                    "details": f"BSSID {a.get('bssid')} on Ch {a.get('channel')} is advertising '{connected_ssid}' with OPEN encryption.",
                    "device_key": str(a.get("bssid") or ""),
                    "ip": "RF",
                    "bssid": str(a.get("bssid") or ""),
                    "mac": str(a.get("bssid") or ""),
                })

    for a in aps:
        sec = a.get("security", "")
        sig = a.get("signal_pct", 0)
        ssid = a.get("ssid", "")
        if "OPEN" in sec.upper() and sig >= 60:
            threats.append({
                "severity": "HIGH",
                "category": "ROGUE_RF_TRANSMITTER",
                "title": f"Close-Proximity Unencrypted Transmitter: {ssid} ({a.get('bssid')})",
                "details": (
                    f"Strong unencrypted 802.11 transmitter '{ssid}' ({a.get('vendor')}) detected at {sig}% "
                    f"({a.get('signal_dbm')} dBm, ~{a.get('est_distance_m')}m on Ch {a.get('channel')}). "
                    "Common signature of Wi-Fi pinhole cameras, IoT provisioning hotspots, or rogue APs."
                ),
                "device_key": str(a.get("bssid") or ""),
                "ip": "RF",
                "bssid": str(a.get("bssid") or ""),
                "mac": str(a.get("bssid") or ""),
            })

    # 3. Include high-risk LAN endpoint findings
    for d in devices:
        if d.get("is_gateway") and d.get("is_online") and d.get("mac"):
            gw_verify = quarantine_engine.verify_gateway_mac(d.get("ip", ""), d.get("mac", ""))
            if gw_verify.get("spoof_detected"):
                threats.append({
                    "severity": "CRITICAL",
                    "category": "GATEWAY_ARP_SPOOF",
                    "title": f"Gateway MAC Address Changed ({gw_verify.get('locked_gateway_mac')} -> {gw_verify.get('observed_mac')})",
                    "details": gw_verify.get("alert", ""),
                    "device_key": d.get("device_key") or d.get("mac") or "",
                    "ip": d.get("ip", ""),
                    "mac": d.get("mac", ""),
                })
        for f in d.get("security_findings", []):
            if f.get("severity") in ("CRITICAL", "HIGH"):
                threats.append({
                    "severity": f["severity"],
                    "category": "LAN_VULNERABILITY",
                    "title": f"{d.get('ip')} ({d.get('display_name')}): {f.get('title')}",
                    "details": f.get("description", ""),
                    "device_key": d.get("device_key") or d.get("mac") or "",
                    "ip": d.get("ip", ""),
                    "mac": d.get("mac", ""),
                })

    return threats


def compute_network_security_posture(
    devices: List[Dict[str, Any]],
    threats: List[Dict[str, str]],
    wifi_spectrum: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute a quantitative 0-100 Subnet Security Posture Score, Letter Grade (A+ to F),
    and 5-Pillar Defense Breakdown across all discovered LAN hosts and 802.11 RF transmitters.
    """
    online_devs = [d for d in devices if d.get("is_online", True)]
    crit_threats = sum(1 for t in threats if t.get("severity") == "CRITICAL")
    high_threats = sum(1 for t in threats if t.get("severity") == "HIGH")

    # Pillar 1: Service Hardening (0-25 pts)
    svc_deduction = 0
    for d in online_devs:
        ports = set(d.get("open_ports") or [])
        if 23 in ports or 5555 in ports or 2375 in ports:
            svc_deduction += 15
        if 445 in ports or 139 in ports or 7547 in ports:
            svc_deduction += 4
    p_service = max(0, 25 - svc_deduction)

    # Pillar 2: Cryptographic Hygiene (0-25 pts)
    crypto_deduction = 0
    for d in online_devs:
        if d.get("smb_info", {}).get("ntlm_relay_vulnerable"):
            crypto_deduction += 8
        if d.get("ssh_info", {}).get("weak_kex") or d.get("ssh_info", {}).get("weak_ciphers"):
            crypto_deduction += 5
        for ps in d.get("port_services") or []:
            if str(ps.get("tls_grade", "")).startswith("F"):
                crypto_deduction += 8
    p_crypto = max(0, 25 - crypto_deduction)

    # Pillar 3: RF Spectrum Defense (0-20 pts)
    aps = wifi_spectrum.get("access_points", [])
    open_close_aps = sum(
        1 for a in aps if "OPEN" in str(a.get("security", "")).upper() and (a.get("signal_pct") or 0) >= 55
    )
    p_rf = max(0, 20 - open_close_aps * 7)

    # Pillar 4: Identity & MAC Accountability (0-15 pts)
    untrusted_rand = sum(
        1
        for d in online_devs
        if d.get("is_randomized_mac") and d.get("trust_state", "known") not in ("trusted",)
    )
    intruders = sum(1 for d in online_devs if d.get("trust_state") == "intruder")
    p_identity = max(0, 15 - untrusted_rand * 2 - intruders * 10)

    # Pillar 5: Gateway & L2 ARP Integrity (0-15 pts)
    arp_mitm = sum(1 for t in threats if t.get("category") in ("ARP_SPOOFING_MITM", "GATEWAY_ARP_SPOOF"))
    gw_http_only = sum(
        1
        for d in online_devs
        if d.get("is_gateway") and 80 in (d.get("open_ports") or []) and 443 not in (d.get("open_ports") or [])
    )
    p_gateway = max(0, 15 - arp_mitm * 15 - gw_http_only * 4)

    total_score = max(0, min(100, p_service + p_crypto + p_rf + p_identity + p_gateway))
    if total_score >= 95:
        grade = "A+"
    elif total_score >= 88:
        grade = "A"
    elif total_score >= 80:
        grade = "B+"
    elif total_score >= 72:
        grade = "B"
    elif total_score >= 62:
        grade = "C"
    elif total_score >= 50:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": total_score,
        "grade": grade,
        "online_hosts_evaluated": len(online_devs),
        "critical_threat_count": crit_threats,
        "high_threat_count": high_threats,
        "pillars": {
            "service_hardening": {"score": p_service, "max": 25, "label": "Service & Port Hardening"},
            "cryptographic_hygiene": {"score": p_crypto, "max": 25, "label": "TLS / SSH / SMB Cryptography"},
            "rf_spectrum_defense": {"score": p_rf, "max": 20, "label": "802.11 RF Spectrum Defense"},
            "identity_accountability": {"score": p_identity, "max": 15, "label": "MAC & Host Trust Accountability"},
            "gateway_integrity": {"score": p_gateway, "max": 15, "label": "Gateway & L2 ARP Integrity"},
        },
    }
