"""
Multi-Vector Active & Passive Network Discovery Probers.
Implements 12 distinct hardware and protocol reconnaissance engines:
1. Interface, CIDR Subnet, & Routing Autodetector
2. Paced Kernel Layer-2 ARP + IPv4/IPv6 Neighbor Table Sweeper
3. Hybrid ICMP + TCP SYN-RST / SYN-ACK Sub-Millisecond Latency & TTL Engine
4. mDNS / DNS-SD / Zeroconf / Bonjour Service & TXT Record Prober
5. SSDP / UPnP / DIAL Multicast Prober & XML Device Descriptor Parser
6. Roku External Control Protocol (ECP) Deep Inspector & Remote Control Engine
7. Spotify Connect ZeroConf Endpoint Inspector
8. Sony PlayStation 4 / PlayStation 5 DDP (Device Discovery Protocol) Prober
9. T-Mobile / Arcadyan 5G NR Gateway Telemetry & Cellular Tower Inspector
10. RFC 1002 NetBIOS Name Service (NBSTAT UDP 137) & Reverse DNS Prober
11. High-Concurrency Multi-Port Scanner, Banner Grabber, HTTP & TLS X.509 Inspector
12. Passive Wire Packet Sniffer (tshark / dumpcap link-layer broadcast capture)
"""

from __future__ import annotations

import concurrent.futures
import errno
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from netpulse.oui import oui_db, unmask_eui64_ipv6_mac


@dataclass
class NetworkInterfaceInfo:
    interface: str
    ip: str
    cidr: str
    netmask: str
    gateway_ip: str
    mac: str
    ipv6_addresses: List[str] = field(default_factory=list)
    ssid: str = ""
    freq_mhz: int = 0
    channel: int = 0
    txpower_dbm: float = 0.0


def detect_active_interface() -> NetworkInterfaceInfo:
    """Autodetect primary active network interface, IPv4 CIDR, MAC, gateway, and Wi-Fi link."""
    iface = "wlo1"
    gateway_ip = "192.168.12.1"
    local_ip = "192.168.12.225"
    cidr = "192.168.12.0/24"
    netmask = "255.255.255.0"
    mac = "00:00:00:00:00:00"
    ipv6_list: List[str] = []

    try:
        route_out = subprocess.check_output(["ip", "-j", "route", "show", "default"], stderr=subprocess.DEVNULL, timeout=5.0).decode()
        routes = json.loads(route_out)
        if routes:
            iface = routes[0].get("dev", iface)
            gateway_ip = routes[0].get("gateway", gateway_ip)
            local_ip = routes[0].get("prefsrc", local_ip)
    except Exception:
        pass

    try:
        addr_out = subprocess.check_output(["ip", "-j", "addr", "show", "dev", iface], stderr=subprocess.DEVNULL, timeout=5.0).decode()
        addrs = json.loads(addr_out)
        if addrs:
            info = addrs[0]
            mac = info.get("address", mac).upper()
            for a in info.get("addr_info", []):
                if a.get("family") == "inet":
                    local_ip = a.get("local", local_ip)
                    prefixlen = a.get("prefixlen", 24)
                    net = ipaddress.IPv4Network(f"{local_ip}/{prefixlen}", strict=False)
                    cidr = str(net)
                    netmask = str(net.netmask)
                elif a.get("family") == "inet6":
                    v6 = a.get("local")
                    if v6:
                        ipv6_list.append(v6)
    except Exception:
        pass

    ssid = ""
    freq_mhz = 0
    channel = 0
    txpower_dbm = 0.0
    try:
        iw_out = subprocess.check_output(["iw", "dev", iface, "info"], stderr=subprocess.DEVNULL, timeout=5.0).decode()
        for line in iw_out.splitlines():
            s = line.strip()
            if s.startswith("ssid "):
                ssid = s[5:].strip()
            elif s.startswith("channel "):
                # e.g. channel 2 (2417 MHz), width: 20 MHz, center1: 2417 MHz
                m = re.search(r"channel\s+(\d+)\s+\((\d+)\s+MHz\)", s)
                if m:
                    channel = int(m.group(1))
                    freq_mhz = int(m.group(2))
            elif s.startswith("txpower "):
                m = re.search(r"([\d.]+)\s+dBm", s)
                if m:
                    txpower_dbm = float(m.group(1))
    except Exception:
        pass

    return NetworkInterfaceInfo(
        interface=iface,
        ip=local_ip,
        cidr=cidr,
        netmask=netmask,
        gateway_ip=gateway_ip,
        mac=mac,
        ipv6_addresses=ipv6_list,
        ssid=ssid,
        freq_mhz=freq_mhz,
        channel=channel,
        txpower_dbm=txpower_dbm,
    )


def read_kernel_neighbors(net_info: NetworkInterfaceInfo) -> Dict[str, Dict[str, Any]]:
    """Read current Linux kernel IPv4 and IPv6 neighbor tables for the active interface."""
    discovered: Dict[str, Dict[str, Any]] = {
        net_info.ip: {
            "ip": net_info.ip,
            "mac": net_info.mac.upper(),
            "neigh_state": "LOCAL_HOST",
            "is_local": True,
            "is_gateway": net_info.ip == net_info.gateway_ip,
            "ipv6_addresses": list(net_info.ipv6_addresses),
        }
    }
    try:
        out = subprocess.check_output(
            ["ip", "-s", "-j", "neigh", "show", "dev", net_info.interface],
            stderr=subprocess.DEVNULL,
            timeout=5.0,
        ).decode()
        entries = json.loads(out)
        mac_to_ipv6: Dict[str, List[str]] = {}
        for entry in entries:
            dst = entry.get("dst", "")
            lladdr = entry.get("lladdr", "").upper()
            if ":" in dst and lladdr:
                mac_to_ipv6.setdefault(lladdr, []).append(dst)

        for entry in entries:
            dst = entry.get("dst", "")
            lladdr = entry.get("lladdr", "").upper()
            state_list = entry.get("state", [])
            state_str = state_list[0] if state_list else "UNKNOWN"
            if "." in dst and lladdr and lladdr != "00:00:00:00:00:00" and state_str not in ("FAILED", "INCOMPLETE"):
                discovered[dst] = {
                    "ip": dst,
                    "mac": lladdr,
                    "neigh_state": state_str,
                    "is_local": False,
                    "is_gateway": dst == net_info.gateway_ip,
                    "ipv6_addresses": mac_to_ipv6.get(lladdr, []),
                    "probes": entry.get("probes", 0),
                }
    except Exception:
        pass
    return discovered


def arp_and_neighbor_sweep(net_info: NetworkInterfaceInfo) -> Dict[str, Dict[str, Any]]:
    """
    Trigger Linux kernel Layer-2 ARP resolution across the entire subnet using paced
    UDP datagrams + concurrent ping sweep, then harvest IPv4 and IPv6 neighbor tables.
    """
    # Snapshot any already-known neighbors before sweep
    discovered = read_kernel_neighbors(net_info)

    network = ipaddress.IPv4Network(net_info.cidr, strict=False)
    host_ips = [str(ip) for ip in network.hosts() if str(ip) != net_info.ip]

    # Step 1: Send 1 UDP packet per IP in 64-host waves to stay within kernel gc_thresh1 (128)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    wave_size = 64
    for i in range(0, len(host_ips), wave_size):
        wave = host_ips[i : i + wave_size]
        for ip in wave:
            try:
                sock.sendto(b"\x00", (ip, 5353))
            except Exception:
                pass
        time.sleep(0.18)
    sock.close()

    # Wait briefly for final wave ARP replies
    time.sleep(0.25)

    # Merge freshly resolved kernel neighbors
    fresh = read_kernel_neighbors(net_info)
    discovered.update(fresh)
    return discovered


def measure_single_host_latency(ip: str, is_local: bool = False) -> Tuple[Optional[float], str, Optional[int]]:
    """
    Measure exact round-trip latency (ms) and IP TTL for a host.
    1. If local host, returns (0.05 ms, 'Loopback', 64).
    2. Tries `ping -c 1 -W 1 <ip>` to get ICMP Echo RTT + TTL.
    3. If host blocks ICMP (Stealth), uses TCP SYN->SYN-ACK / SYN->RST timing across candidate ports.
    """
    if is_local:
        return (0.05, "Local Interface", 64)

    # Try ICMP Echo first for TTL + RTT
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            timeout=1.4,
        )
        if res.returncode == 0:
            m_time = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            m_ttl = re.search(r"ttl=(\d+)", res.stdout, re.IGNORECASE)
            rtt = float(m_time.group(1)) if m_time else 1.0
            ttl = int(m_ttl.group(1)) if m_ttl else None
            return (round(rtt, 2), "ICMP Echo", ttl)
    except Exception:
        pass

    # Fallback: TCP SYN -> SYN-ACK or TCP SYN -> RST handshake timer
    for port in (62078, 8060, 4070, 80, 443, 41800):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.45)
        t0 = time.perf_counter()
        try:
            err = s.connect_ex((ip, port))
            dt_ms = (time.perf_counter() - t0) * 1000.0
            s.close()
            if err == 0:
                return (round(dt_ms, 2), f"TCP SYN-ACK (:{port})", None)
            if err == errno.ECONNREFUSED:
                return (round(dt_ms, 2), f"TCP SYN-RST (:{port})", None)
        except Exception:
            s.close()

    return (None, "Layer-2 ARP Response", None)


def decode_avahi_escapes(val: str) -> str:
    """Decode avahi-browse decimal escape sequences like \\032 -> space."""
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), val)


def probe_mdns_services(interface: str = "wlo1") -> Dict[str, List[Dict[str, Any]]]:
    """
    Harvest all mDNS / DNS-SD / Bonjour services on the LAN via avahi-browse.
    Returns mapping of IP -> list of service dictionaries (service_type, instance_name, hostname, port, txt_dict).
    """
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    try:
        out = subprocess.check_output(
            ["avahi-browse", "-a", "-t", "-r", "-p"],
            stderr=subprocess.DEVNULL,
            timeout=5.0,
        ).decode("utf-8", errors="ignore")

        for line in out.splitlines():
            if not line.startswith("="):
                continue
            parts = line.split(";")
            if len(parts) < 10:
                continue
            iface = parts[1]
            proto = parts[2]
            if iface not in (interface, "lo") or proto != "IPv4":
                continue
            instance_name = decode_avahi_escapes(parts[3])
            service_type = decode_avahi_escapes(parts[4])
            hostname = decode_avahi_escapes(parts[6])
            ip = parts[7]
            try:
                port = int(parts[8])
            except ValueError:
                port = 0
            raw_txt = ";".join(parts[9:]).strip()

            # Parse quoted TXT pairs: "k1=v1" "k2=v2"
            txt_dict: Dict[str, str] = {}
            for match in re.finditer(r'"([^"]*)"', raw_txt):
                kv = decode_avahi_escapes(match.group(1))
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    txt_dict[k.strip()] = v.strip()
                elif kv:
                    txt_dict[kv] = "true"

            svc_entry = {
                "instance": instance_name,
                "service": service_type,
                "service_type": service_type,
                "instance_name": instance_name,
                "hostname": hostname,
                "port": port,
                "txt": txt_dict,
            }
            existing = by_ip.setdefault(ip, [])
            if svc_entry not in existing:
                existing.append(svc_entry)
    except Exception:
        pass
    return by_ip


def _strip_xml_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def fetch_upnp_xml_descriptor(location_url: str) -> Dict[str, Any]:
    """Download and parse a UPnP / DIAL XML device description document."""
    info: Dict[str, Any] = {"location": location_url}
    try:
        req = urllib.request.Request(location_url, headers={"User-Agent": "NetPulse/2.0 UPnP/1.1"})
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            xml_bytes = resp.read(65536)
        root = ET.fromstring(xml_bytes)
        for elem in root.iter():
            tag = _strip_xml_ns(elem.tag)
            text = (elem.text or "").strip()
            if tag in (
                "friendlyName",
                "manufacturer",
                "manufacturerURL",
                "modelDescription",
                "modelName",
                "modelNumber",
                "modelURL",
                "serialNumber",
                "UDN",
                "deviceType",
                "presentationURL",
            ) and text and tag not in info:
                info[tag] = text
            elif tag == "icon":
                icon_url = None
                mime = ""
                for child in elem:
                    ctag = _strip_xml_ns(child.tag)
                    if ctag == "url" and child.text:
                        icon_url = urllib.parse.urljoin(location_url, child.text.strip())
                    elif ctag == "mimetype" and child.text:
                        mime = child.text.strip()
                if icon_url and ("png" in mime or icon_url.endswith(".png") or "icon_url" not in info):
                    info["icon_url"] = icon_url
    except Exception:
        pass
    return info


def probe_ssdp_upnp(timeout: float = 1.6) -> Dict[str, Dict[str, Any]]:
    """
    Send SSDP M-SEARCH multicast bursts across ssdp:all, upnp:rootdevice, and DIAL,
    then fetch and parse XML device descriptions concurrently.
    """
    by_ip: Dict[str, Dict[str, Any]] = {}
    locations_by_ip: Dict[str, Set[str]] = {}
    servers_by_ip: Dict[str, str] = {}
    wakeup_by_ip: Dict[str, str] = {}
    usns_by_ip: Dict[str, List[str]] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.25)
    for st in ("ssdp:all", "upnp:rootdevice", "urn:dial-multiscreen-org:service:dial:1"):
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            f"ST: {st}\r\n\r\n"
        ).encode("ascii")
        try:
            sock.sendto(msg, ("239.255.255.250", 1900))
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            text = data.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                lower = line.lower()
                if lower.startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    if loc:
                        locations_by_ip.setdefault(ip, set()).add(loc)
                elif lower.startswith("server:"):
                    srv = line.split(":", 1)[1].strip()
                    if srv:
                        servers_by_ip[ip] = srv
                elif lower.startswith("wakeup:"):
                    wval = line.split(":", 1)[1].strip()
                    if wval:
                        wakeup_by_ip[ip] = wval
                elif lower.startswith("usn:"):
                    uval = line.split(":", 1)[1].strip()
                    if uval and uval not in usns_by_ip.setdefault(ip, []):
                        usns_by_ip[ip].append(uval)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()

    # Fetch XML descriptors concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        future_map = {}
        for ip, locs in locations_by_ip.items():
            # Prefer port 8060 root XML before dial/dd.xml so we get full Roku metadata
            sorted_locs = sorted(locs, key=lambda u: (0 if u.endswith(":8060/") else 1, len(u)))
            for loc in sorted_locs[:2]:
                future_map[ex.submit(fetch_upnp_xml_descriptor, loc)] = ip

        for fut, ip in future_map.items():
            try:
                xml_info = fut.result(timeout=2.2)
                merged = by_ip.setdefault(ip, {})
                if ip in servers_by_ip and "server" not in merged:
                    merged["server"] = servers_by_ip[ip]
                if ip in wakeup_by_ip:
                    merged["ssdp_wakeup"] = wakeup_by_ip[ip]
                if ip in usns_by_ip:
                    merged["ssdp_usns"] = usns_by_ip[ip]
                for k, v in xml_info.items():
                    if v and k not in merged:
                        merged[k] = v
            except Exception:
                pass

    return by_ip


DIAL_KNOWN_APPS: List[str] = [
    "Netflix",
    "AmazonInstantVideo",
    "PlutoTV",
    "ParamountPlus",
    "YouTube",
    "Hulu",
    "DisneyPlus",
    "Max",
    "Peacock",
    "AppleTV",
    "Plex",
    "Tubi",
    "Spotify",
]


def probe_dial_apps(ip: str, port: int = 8060) -> List[Dict[str, Any]]:
    """
    Probe DIAL v2.1 application endpoints (http://<ip>:8060/dial/<App>) concurrently.
    Works unauthenticated even when Roku OS 16.0.4 has ecp-setting-mode=limited.
    """
    apps_found: List[Dict[str, Any]] = []

    def _check_app(app_name: str) -> Optional[Dict[str, Any]]:
        url = f"http://{ip}:{port}/dial/{app_name}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/3.0 DIAL/2.1"})
            with urllib.request.urlopen(req, timeout=0.6) as resp:
                xml_txt = resp.read(8192).decode("utf-8", errors="ignore")
                st_m = re.search(r"<state>([^<]+)</state>", xml_txt, re.IGNORECASE)
                state_str = st_m.group(1).strip() if st_m else "unknown"
                allow_stop = 'allowStop="true"' in xml_txt
                return {
                    "name": app_name,
                    "state": state_str,
                    "allow_stop": allow_stop,
                    "url": url,
                }
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(_check_app, DIAL_KNOWN_APPS):
            if res is not None:
                apps_found.append(res)
    return apps_found


def control_dial_app(ip: str, app_name: str, action: str = "launch", port: int = 8060, payload: str = "") -> Tuple[bool, str]:
    """
    Launch (POST /dial/<App>) or Stop (DELETE /dial/<App>/run) a DIAL v2.1 application
    directly on a Smart TV or Streaming Stick over the LAN. Supports optional deep-link launch payloads.
    """
    clean_app = urllib.parse.quote(app_name.strip())
    if action == "stop":
        url = f"http://{ip}:{port}/dial/{clean_app}/run"
        req = urllib.request.Request(url, method="DELETE", headers={"User-Agent": "NetPulse/3.0 DIAL/2.1"})
    else:
        url = f"http://{ip}:{port}/dial/{clean_app}"
        body_bytes = payload.encode("utf-8") if payload else b""
        req = urllib.request.Request(
            url,
            data=body_bytes,
            method="POST",
            headers={"Content-Type": "text/plain; charset=utf-8", "User-Agent": "NetPulse/3.0 DIAL/2.1"},
        )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            extra = f" (payload='{payload}')" if payload else ""
            return (resp.status in (200, 201, 204), f"DIAL {action.upper()} '{app_name}'{extra} on {ip}:{port} -> HTTP {resp.status}")
    except urllib.error.HTTPError as he:
        return (False, f"DIAL {action.upper()} '{app_name}' returned HTTP {he.code}: {he.reason}")
    except Exception as e:
        return (False, str(e))


def probe_roku_ecp(ip: str) -> Optional[Dict[str, Any]]:
    """
    Deep-inspect a Roku OS TV or Streaming Stick via External Control Protocol (TCP 8060)
    and DIAL v2.1 application state discovery.
    """
    info: Dict[str, Any] = {}
    try:
        url = f"http://{ip}:8060/query/device-info"
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/3.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            xml_data = resp.read(65536)
        root = ET.fromstring(xml_data)
        for child in root:
            tag = _strip_xml_ns(child.tag)
            val = (child.text or "").strip()
            if val:
                info[tag] = val
        info["device_image_url"] = f"http://{ip}:8060/device-image.png"
    except Exception:
        return None

    if not info:
        return None

    # Query currently running app and active screensaver on the TV / Stick via ECP
    try:
        app_url = f"http://{ip}:8060/query/active-app"
        with urllib.request.urlopen(app_url, timeout=0.9) as resp:
            app_root = ET.fromstring(resp.read(16384))
            for child in app_root:
                ctag = _strip_xml_ns(child.tag)
                if ctag == "app" and child.text:
                    info["active_app"] = child.text.strip()
                    info["active_app_id"] = child.attrib.get("id", "")
                    info["active_app_version"] = child.attrib.get("version", "")
                    info["active_app_type"] = child.attrib.get("type", "")
                    info["active_app_ui_location"] = child.attrib.get("ui-location", "")
                elif ctag == "screensaver" and child.text:
                    info["screensaver_name"] = child.text.strip()
                    info["screensaver_id"] = child.attrib.get("id", "")
                    info["screensaver_version"] = child.attrib.get("version", "")
    except Exception:
        pass

    # Always probe DIAL v2.1 apps (works even when ecp-setting-mode == limited)
    dial_apps = probe_dial_apps(ip, 8060)
    info["dial_apps"] = dial_apps
    for dapp in dial_apps:
        if dapp.get("state") == "running" and (not info.get("active_app") or info.get("active_app") == "Roku Dynamic Menu"):
            info["active_app"] = dapp["name"]

    return info


def send_roku_keypress(ip: str, key: str) -> Tuple[bool, str]:
    """
    Send a live Roku ECP remote control keypress (e.g., Home, VolumeMute, VolumeUp, VolumeDown,
    PowerOff, PowerOn, Select, Up, Down, Left, Right, Back, Play, Info, FindRemote).
    """
    allowed_keys = {
        "Home", "Rev", "Fwd", "Play", "Select", "Left", "Right", "Down", "Up",
        "Back", "InstantReplay", "Info", "Backspace", "Search", "Enter",
        "FindRemote", "VolumeDown", "VolumeMute", "VolumeUp", "PowerOff", "PowerOn",
        "ChannelUp", "ChannelDown", "InputTuner", "InputHDMI1", "InputHDMI2", "InputHDMI3",
    }
    if key not in allowed_keys:
        return (False, f"Unsupported Roku ECP key '{key}'")
    try:
        url = f"http://{ip}:8060/keypress/{urllib.parse.quote(key)}"
        req = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return (resp.status in (200, 204), f"Roku ECP keypress/{key} -> HTTP {resp.status}")
    except Exception as e:
        return (False, str(e))


def probe_spotify_connect(ip: str, mdns_services: List[Dict[str, Any]], open_ports: List[int]) -> Optional[Dict[str, Any]]:
    """
    Query Spotify Connect ZeroConf API (?action=getInfo) to extract exact speaker/console/TV brand,
    model, deviceType, aliases (e.g., 'Melinda's Echo Dot'), and libraryVersion.
    """
    candidate_urls: List[str] = []
    for svc in mdns_services:
        if "_spotify-connect" in svc.get("service", "") or "Spotify" in svc.get("instance", ""):
            port = svc.get("port", 0)
            cpath = svc.get("txt", {}).get("CPath", "/zc")
            if port > 0:
                candidate_urls.append(f"http://{ip}:{port}{cpath}?action=getInfo")

    if 4070 in open_ports:
        candidate_urls.append(f"http://{ip}:4070/spotifyConnect?action=getInfo")
    if 41800 in open_ports:
        candidate_urls.append(f"http://{ip}:41800/spConn?action=getInfo")

    for url in candidate_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/2.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read(32768).decode("utf-8", errors="ignore"))
                if isinstance(data, dict) and ("brandDisplayName" in data or "remoteName" in data or "deviceType" in data):
                    data["endpoint_url"] = url
                    return data
        except Exception:
            continue
    return None


def probe_playstation_ddp(ip: str) -> Optional[Dict[str, Any]]:
    """
    Probe Sony PlayStation 4 (UDP 987) and PlayStation 5 (UDP 9302) Device Discovery Protocol (DDP).
    Extracts exact console generation, hostname, hardware host-id, system firmware version, and power state.
    """
    payload = b"SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:00030010\r\n\r\n"
    for port in (9302, 987):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.35)
        try:
            s.sendto(payload, (ip, port))
            data, _ = s.recvfrom(2048)
            s.close()
            text = data.decode("utf-8", errors="ignore")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if not lines:
                continue
            status_line = lines[0]  # e.g., HTTP/1.1 200 Ok or HTTP/1.1 620 Server Standby
            parsed: Dict[str, Any] = {
                "ddp_port": port,
                "status_line": status_line,
                "power_state": "STANDBY (Rest Mode)" if "620" in status_line else "ACTIVE (Awake)",
            }
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    parsed[k.strip().lower()] = v.strip()

            sys_ver = parsed.get("system-version", "")
            if len(sys_ver) >= 4 and sys_ver[:4].isdigit():
                maj = int(sys_ver[:2])
                minor = sys_ver[2:4]
                parsed["firmware_formatted"] = f"{maj}.{minor} (Build {sys_ver})"
            return parsed
        except Exception:
            s.close()
            continue
    return None


def probe_airplay_bplist(ip: str, open_ports: List[int]) -> Optional[Dict[str, Any]]:
    """
    Decode Apple AirPlay Receiver Binary Plist (bplist00) at http://<ip>:7000/info.
    Extracts hardwareRevision (e.g. PVT1), firmwareBuildDate, AirPlay SDK version,
    FairPlay DRM version, and physical 4K/DolbyVision/HDR10 display EDID specifications.
    """
    if 7000 not in open_ports:
        return None
    try:
        req = urllib.request.Request(f"http://{ip}:7000/info", headers={"User-Agent": "AirPlay/680.19.1"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            raw = resp.read(65536)
        if raw.startswith(b"bplist") or raw.startswith(b"<?xml"):
            pl = plistlib.loads(raw)
            if isinstance(pl, dict):
                pl.pop("audioLatencies", None)
                displays = pl.get("displays", [])
                if displays and isinstance(displays[0], dict):
                    d0 = displays[0]
                    w_max = d0.get("widthPixelsMax", d0.get("widthPixels", 0))
                    h_max = d0.get("heightPixelsMax", d0.get("heightPixels", 0))
                    fps = d0.get("maxFPS", 60)
                    hdr_modes = [
                        m.get("HDRMode", "")
                        for m in d0.get("HDRSupportedModes", [])
                        if isinstance(m, dict) and m.get("HDRMode")
                    ]
                    pl["display_summary"] = f"{w_max}x{h_max} @{fps}Hz ({', '.join(hdr_modes) or 'SDR'})"
                return pl
    except Exception:
        pass
    return None


def probe_onvif_ws_discovery(timeout: float = 1.4) -> List[Dict[str, Any]]:
    """
    Broadcast SOAP XML WS-Discovery Probe to 239.255.255.250:3702 (UDP) to detect
    ONVIF IP Cameras, NVRs, and Network Video Transmitters on the local subnet.
    """
    msg_id = f"uuid:{uuid.uuid4()}"
    soap_probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        f"<e:Header><w:MessageID>{msg_id}</w:MessageID>"
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        "</e:Header>"
        "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>"
        "</e:Envelope>"
    ).encode("utf-8")

    discovered: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.35)
    try:
        sock.sendto(soap_probe, ("239.255.255.250", 3702))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
                ip = addr[0]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    txt = data.decode("utf-8", errors="ignore")
                    xaddrs = re.findall(r"<[^:>]*:?XAddrs>([^<]+)</", txt)
                    scopes = re.findall(r"<[^:>]*:?Scopes>([^<]+)</", txt)
                    discovered.append({
                        "ip": ip,
                        "xaddrs": xaddrs[0].strip() if xaddrs else "",
                        "scopes": scopes[0].strip() if scopes else "",
                    })
            except socket.timeout:
                continue
    except Exception:
        pass
    finally:
        sock.close()
    return discovered


def probe_tmobile_gateway(ip: str) -> Optional[Dict[str, Any]]:
    """
    Query T-Mobile / Arcadyan / Sagemcom 5G Home Internet Gateway API (/TMI/v1/gateway?get=all).
    Extracts gateway hardware metadata and real-time 5G NR cellular tower signal telemetry.
    """
    url = f"http://{ip}/TMI/v1/gateway?get=all"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/4.2"})
        with urllib.request.urlopen(req, timeout=2.8) as resp:
            data = json.loads(resp.read(65536).decode("utf-8", errors="ignore"))
            if isinstance(data, dict) and ("device" in data or "signal" in data):
                return data
    except Exception:
        pass
    return None


def probe_netbios_and_rdns(ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Perform Reverse DNS lookup and RFC 1002 NetBIOS Name Service (UDP 137 NBSTAT) query.
    Returns (rdns_hostname, netbios_name, netbios_workgroup).
    """
    rdns_name: Optional[str] = None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            rdns_name = host
    except Exception:
        pass

    # RFC 1002 NBSTAT Wildcard Query (*)
    nb_name: Optional[str] = None
    nb_group: Optional[str] = None
    packet = (
        b"\xa5\xd8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.sendto(packet, (ip, 137))
        resp, _ = s.recvfrom(1024)
        s.close()
        if len(resp) > 57:
            num_names = resp[56]
            offset = 57
            for _ in range(num_names):
                if offset + 18 > len(resp):
                    break
                raw_n = resp[offset : offset + 15].decode("ascii", errors="ignore").strip()
                suffix = resp[offset + 15]
                flags = struct.unpack("!H", resp[offset + 16 : offset + 18])[0]
                is_group = bool(flags & 0x8000)
                if raw_n and not raw_n.startswith("\x01\x02"):
                    if not is_group and suffix in (0x00, 0x20) and not nb_name:
                        nb_name = raw_n
                    elif is_group and suffix == 0x00 and not nb_group:
                        nb_group = raw_n
                offset += 18
    except Exception:
        s.close()

    return (rdns_name, nb_name, nb_group)


# Standard + IoT + Smart TV + Console + Admin TCP ports
STANDARD_SCAN_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    81: "HTTP-Alt",
    88: "Kerberos",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS-SSN",
    443: "HTTPS",
    445: "SMB / CIFS",
    515: "LPD Printer",
    548: "AFP (Apple Filing)",
    554: "RTSP Camera Stream",
    631: "IPP / CUPS Printer",
    873: "Rsync",
    1080: "Alexa / SOCKS Transport",
    1337: "Custom Service",
    1400: "Sonos ZonePlayer UPnP",
    1883: "MQTT IoT Broker",
    2049: "NFS",
    2375: "Docker Engine API",
    2376: "Docker TLS API",
    3000: "Web Dev / LG webOS WS",
    3001: "LG webOS WSS Control",
    3306: "MySQL",
    3389: "RDP",
    4070: "Spotify Connect (Echo/IoT)",
    4222: "NATS Messaging",
    5000: "UPnP / Synology / Flask",
    5353: "mDNS",
    5432: "PostgreSQL",
    5541: "Alexa Local Transport",
    5555: "Android ADB",
    5900: "VNC Remote Desktop",
    6379: "Redis",
    7000: "AirPlay Receiver",
    7250: "Roku Display Service",
    7547: "TR-069 / CWMP Carrier Mgmt",
    8000: "HTTP-Alt / Media",
    8001: "Samsung Tizen SmartView HTTP",
    8002: "Samsung Tizen SmartView TLS",
    8008: "Google Cast HTTP",
    8009: "Google Cast TLS",
    8060: "Roku ECP Control",
    8061: "Roku ECP-TLS (X.509)",
    8080: "HTTP Proxy / Admin",
    8443: "HTTPS Admin",
    8554: "RTSP-Alt Stream",
    8883: "MQTT-TLS",
    8888: "Alexa / Web Console",
    9000: "Portainer / Sonar",
    9050: "Tor SOCKS Proxy",
    9080: "Netflix NRDP / MDX",
    9100: "JetDirect Printer",
    9295: "PlayStation Remote Play",
    9999: "TP-Link Kasa Smart Home Protocol",
    11434: "Ollama AI Server",
    32400: "Plex Media Server",
    39395: "Apple HomeKit / Roku IPC",
    39741: "Spotify Connect ZeroConf",
    41800: "Spotify Connect (PlayStation/TV)",
    45438: "Spotify Connect ZeroConf",
    47781: "Roku UPnP / Media Service",
    49152: "UPnP IGD SOAP",
    55442: "Amazon WHALEXA Audio HTTP",
    55443: "Amazon WHALEXA Audio TLS",
    55445: "Amazon WHALEXA Sync",
    62078: "Apple iOS Lockdownd",
}


def inspect_http_or_tls_port(ip: str, port: int) -> Dict[str, Any]:
    """Grab HTTP Server header, HTML <title>, RP headers, or TLS X.509 certificate metadata on an open port."""
    meta: Dict[str, Any] = {}
    is_tls = port in (443, 8009, 8061, 8443, 8883, 8888, 55443)

    if is_tls:
        try:
            p = subprocess.run(
                ["openssl", "s_client", "-connect", f"{ip}:{port}", "-servername", ip],
                input="",
                capture_output=True,
                text=True,
                timeout=1.4,
            )
            if "Protocol  :" in p.stdout:
                m_pr = re.search(r"Protocol\s*:\s*(\S+)", p.stdout)
                if m_pr:
                    meta["tls_version"] = m_pr.group(1)
            if "Cipher    :" in p.stdout:
                m_ci = re.search(r"Cipher\s*:\s*(\S+)", p.stdout)
                if m_ci:
                    meta["tls_cipher"] = m_ci.group(1)
            if "BEGIN CERTIFICATE" in p.stdout:
                x = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial", "-fingerprint", "-sha256"],
                    input=p.stdout,
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                )
                for ln in x.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("subject="):
                        meta["cert_subject"] = ln.split("=", 1)[1].strip()
                    elif ln.startswith("issuer="):
                        meta["cert_issuer"] = ln.split("=", 1)[1].strip()
                    elif ln.startswith("notBefore="):
                        meta["cert_not_before"] = ln.split("=", 1)[1].strip()
                    elif ln.startswith("notAfter="):
                        meta["cert_not_after"] = ln.split("=", 1)[1].strip()
                    elif ln.startswith("serial="):
                        meta["cert_serial"] = ln.split("=", 1)[1].strip()
                    elif "Fingerprint=" in ln:
                        meta["cert_sha256"] = ln.split("=", 1)[1].strip()
                subj = meta.get("cert_subject", "")
                iss = meta.get("cert_issuer", "")
                if subj and iss:
                    meta["cert_self_signed"] = subj == iss
            tls_v = meta.get("tls_version", "")
            if "1.3" in tls_v:
                meta["tls_grade"] = "B (Self-Signed TLS 1.3)" if meta.get("cert_self_signed") else "A+"
            elif "1.2" in tls_v:
                meta["tls_grade"] = "B (Self-Signed TLS 1.2)" if meta.get("cert_self_signed") else "A"
            elif tls_v:
                meta["tls_grade"] = "F (Deprecated TLS)"
        except Exception:
            pass

    if port in (80, 81, 443, 1337, 2375, 3000, 4070, 5000, 7000, 7547, 8000, 8008, 8060, 8061, 8080, 8443, 8888, 9080, 9295, 11434, 32400, 55442, 55443):
        scheme = "https" if is_tls else "http"
        try:
            ctx = ssl._create_unverified_context() if is_tls else None
            req = urllib.request.Request(f"{scheme}://{ip}:{port}/", headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=1.2, context=ctx) as resp:
                srv = resp.headers.get("Server")
                if srv:
                    meta["server"] = srv
                rp_ver = resp.headers.get("RP-Version")
                if rp_ver:
                    meta["rp_version"] = rp_ver
                    meta["rp_reason"] = resp.headers.get("RP-Application-Reason", "")
                missing_hdrs: List[str] = []
                for h_name in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
                    if not resp.headers.get(h_name):
                        missing_hdrs.append(h_name)
                meta["missing_security_headers"] = missing_hdrs
                ctype = resp.headers.get("Content-Type", "")
                body = resp.read(8192).decode("utf-8", errors="ignore")
                m_title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m_title:
                    meta["http_title"] = re.sub(r"\s+", " ", m_title.group(1)).strip()[:120]
                elif "json" in ctype.lower() and body:
                    meta["http_snippet"] = body[:140]
        except urllib.error.HTTPError as he:
            srv = he.headers.get("Server") if he.headers else None
            if srv:
                meta["server"] = srv
            if he.headers and he.headers.get("RP-Version"):
                meta["rp_version"] = he.headers.get("RP-Version", "")
                meta["rp_reason"] = he.headers.get("RP-Application-Reason", "")
            meta["http_status"] = he.code
        except Exception:
            pass
    elif port == 22:
        try:
            with socket.create_connection((ip, 22), timeout=0.8) as s:
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    meta["banner"] = banner[:120]
        except Exception:
            pass

    return meta


def scan_ports_and_banners(ip: str, extra_ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """Concurrently scan standard + dynamically discovered ports on a host and grab banners."""
    ports_to_check = dict(STANDARD_SCAN_PORTS)
    if extra_ports:
        for p in extra_ports:
            if p > 0 and p not in ports_to_check:
                ports_to_check[p] = "Dynamic mDNS/UPnP Service"

    open_ports: List[int] = []

    def _try_port(port: int) -> Optional[int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.22)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        for res in ex.map(_try_port, sorted(ports_to_check.keys())):
            if res is not None:
                open_ports.append(res)

    results: List[Dict[str, Any]] = []
    for port in sorted(open_ports):
        meta = inspect_http_or_tls_port(ip, port)
        results.append({
            "port": port,
            "protocol": "TCP",
            "service": ports_to_check.get(port, "TCP Service"),
            "banner": meta.get("banner") or meta.get("server") or meta.get("http_title") or meta.get("cert_subject") or "",
            "http_title": meta.get("http_title", ""),
            "server": meta.get("server", ""),
            "tls_version": meta.get("tls_version", ""),
            "tls_cipher": meta.get("tls_cipher", ""),
            "cert_subject": meta.get("cert_subject", ""),
            "cert_issuer": meta.get("cert_issuer", ""),
            "cert_serial": meta.get("cert_serial", ""),
            "cert_not_before": meta.get("cert_not_before", ""),
            "cert_not_after": meta.get("cert_not_after", ""),
            "cert_sha256": meta.get("cert_sha256", ""),
            "cert_self_signed": meta.get("cert_self_signed", False),
            "tls_grade": meta.get("tls_grade", ""),
            "missing_security_headers": meta.get("missing_security_headers", []),
            "rp_version": meta.get("rp_version", ""),
            "rp_reason": meta.get("rp_reason", ""),
        })

    return results


def send_wake_on_lan(mac: str, broadcast_ip: str = "255.255.255.255") -> Tuple[bool, str]:
    """Transmit IEEE 802 Wake-on-LAN (WoL) Magic Packet (6x 0xFF + 16x MAC) to UDP ports 9 and 7."""
    clean = mac.strip().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) != 12 or not all(c in "0123456789ABCDEFabcdef" for c in clean):
        return (False, f"Invalid hardware MAC address: {mac}")
    mac_bytes = bytes.fromhex(clean)
    magic_packet = b"\xff" * 6 + mac_bytes * 16
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for port in (9, 7):
            sock.sendto(magic_packet, (broadcast_ip, port))
            if broadcast_ip != "255.255.255.255":
                sock.sendto(magic_packet, ("255.255.255.255", port))
        sock.close()
        return (True, f"Transmitted 102-byte Magic Packet for {mac.upper()} to {broadcast_ip}:9/UDP")
    except Exception as e:
        return (False, str(e))


def send_playstation_wakeup(ip: str, mac: str = "", host_id: str = "") -> Dict[str, Any]:
    """
    Send Sony PlayStation DDP WAKEUP packets to UDP 987 (PS4) and UDP 9302 (PS5),
    plus IEEE 802 Wake-on-LAN Magic Packets to both the Wi-Fi MAC and Primary Hardware Host-ID.
    """
    actions: List[str] = []
    if mac:
        _, m1 = send_wake_on_lan(mac)
        actions.append(m1)
    if len(host_id) == 12:
        formatted_hid = ":".join(host_id[i : i + 2] for i in range(0, 12, 2))
        if formatted_hid.upper() != mac.upper():
            _, m2 = send_wake_on_lan(formatted_hid)
            actions.append(m2)

    ddp_wake = (
        "WAKEUP * HTTP/1.1\r\n"
        "client-type:vr\r\n"
        "auth-type:C\r\n"
        "model:w\r\n"
        "app-type:r\r\n"
        "device-discovery-protocol-version:00030010\r\n\r\n"
    ).encode("ascii")

    for port in (987, 9302):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.35)
        try:
            s.sendto(ddp_wake, (ip, port))
            actions.append(f"Sent PlayStation DDP WAKEUP frame to {ip}:{port}/UDP")
        except Exception as e:
            actions.append(f"DDP {ip}:{port} error: {e}")
        finally:
            s.close()

    status_now = probe_playstation_ddp(ip)
    return {
        "ip": ip,
        "actions_executed": actions,
        "current_ddp_status": status_now,
    }


def control_spotify_zeroconf(ip: str, endpoint_url: str = "", action: str = "getInfo") -> Dict[str, Any]:
    """
    Interact with a Spotify Connect ZeroConf endpoint (Amazon Echo, Roku TV, PlayStation).
    Supports 'getInfo' (live session/device inspection) and 'resetUsers' (disconnect active session).
    """
    base_url = endpoint_url.split("?")[0] if endpoint_url else f"http://{ip}:4070/spotifyConnect"
    try:
        if action == "resetUsers":
            data_bytes = urllib.parse.urlencode({"action": "resetUsers"}).encode("utf-8")
            req = urllib.request.Request(base_url, data=data_bytes, method="POST", headers={"User-Agent": "NetPulse/3.0"})
        else:
            req = urllib.request.Request(f"{base_url}?action=getInfo", headers={"User-Agent": "NetPulse/3.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            raw = resp.read(32768).decode("utf-8", errors="ignore")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"raw": raw}
            return {"ok": True, "action": action, "endpoint": base_url, "response": parsed}
    except Exception as e:
        return {"ok": False, "action": action, "endpoint": base_url, "error": str(e)}


def probe_http_endpoint_custom(ip: str, port: int, path: str = "/", method: str = "GET") -> Dict[str, Any]:
    """Send an interactive HTTP/HTTPS request from the workbench to any LAN host/port."""
    clean_path = path if path.startswith("/") else f"/{path}"
    scheme = "https" if port in (443, 8443, 8009) else "http"
    url = f"{scheme}://{ip}:{port}{clean_path}"
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(
            url,
            data=b"" if method.upper() == "POST" else None,
            method=method.upper(),
            headers={"User-Agent": "NetPulse-Workbench/3.0"},
        )
        with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
            body = resp.read(32768).decode("utf-8", errors="ignore")
            elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                "ok": True,
                "url": url,
                "status": resp.status,
                "elapsed_ms": elapsed,
                "headers": dict(resp.headers),
                "body": body[:4000],
            }
    except urllib.error.HTTPError as he:
        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        return {
            "ok": False,
            "url": url,
            "status": he.code,
            "elapsed_ms": elapsed,
            "headers": dict(he.headers) if he.headers else {},
            "body": he.read(4096).decode("utf-8", errors="ignore") if he.fp else str(he),
        }
    except Exception as e:
        return {"ok": False, "url": url, "error": str(e)}


def send_roku_text(ip: str, text: str) -> Dict[str, Any]:
    """
    Transmit a full text string to a Roku TV / Stick via ECP Lit_<url-encoded-char> keypresses,
    plus query the current /query/active-app state.
    """
    sent = 0
    errors: List[str] = []
    for ch in text[:120]:
        encoded_ch = urllib.parse.quote(ch, safe="")
        url = f"http://{ip}:8060/keypress/Lit_{encoded_ch}"
        try:
            req = urllib.request.Request(url, data=b"", method="POST")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status in (200, 204):
                    sent += 1
        except Exception as e:
            errors.append(str(e))
            break
    info = probe_roku_ecp(ip) or {}
    return {
        "ok": sent > 0 and not errors,
        "ip": ip,
        "text_sent": text[:sent],
        "chars_transmitted": sent,
        "active_app": info.get("active_app", ""),
        "active_app_version": info.get("active_app_version", ""),
        "screensaver": info.get("screensaver_name", ""),
        "errors": errors,
    }


def scan_custom_port_range(ip: str, start_port: int = 1, end_port: int = 65535) -> Dict[str, Any]:
    """High-speed concurrent TCP port range scanner (up to all 65,535 ports) with HTTP & X.509 inspection."""
    start_p = max(1, min(65535, start_port))
    end_p = max(start_p, min(65535, end_port))

    t0 = time.perf_counter()
    open_ports: List[int] = []

    def _check(p: int) -> Optional[int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.16)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as ex:
        for res in ex.map(_check, range(start_p, end_p + 1)):
            if res is not None:
                open_ports.append(res)

    detailed: List[Dict[str, Any]] = []
    for p in sorted(open_ports):
        meta = inspect_http_or_tls_port(ip, p)
        detailed.append({
            "port": p,
            "service": STANDARD_SCAN_PORTS.get(p, "TCP Service"),
            "server": meta.get("server", ""),
            "http_title": meta.get("http_title", ""),
            "banner": meta.get("banner", ""),
            "tls_version": meta.get("tls_version", ""),
            "tls_cipher": meta.get("tls_cipher", ""),
            "cert_subject": meta.get("cert_subject", ""),
            "cert_issuer": meta.get("cert_issuer", ""),
            "cert_serial": meta.get("cert_serial", ""),
            "cert_not_before": meta.get("cert_not_before", ""),
            "cert_not_after": meta.get("cert_not_after", ""),
            "cert_sha256": meta.get("cert_sha256", ""),
            "cert_self_signed": meta.get("cert_self_signed", False),
            "tls_grade": meta.get("tls_grade", ""),
            "missing_security_headers": meta.get("missing_security_headers", []),
            "rp_version": meta.get("rp_version", ""),
            "rp_reason": meta.get("rp_reason", ""),
        })

    return {
        "ip": ip,
        "range": f"{start_p}-{end_p}",
        "ports_scanned": (end_p - start_p + 1),
        "duration_sec": round(time.perf_counter() - t0, 2),
        "open_ports": detailed,
    }


def control_tmobile_gateway(
    ip: str = "192.168.12.1",
    action: str = "telemetry",
    username: str = "admin",
    password: str = "",
) -> Dict[str, Any]:
    """
    Query and control the T-Mobile 5G Home Internet Gateway (/TMI/v1/*).
    - Without a password, retrieves full unauthenticated /TMI/v1/gateway?get=all & /TMI/v1/version.
    - With the Gateway Admin password, authenticates via POST /TMI/v1/auth/login to retrieve:
      * /TMI/v1/network/telemetry?get=all (connected Wi-Fi clients, per-client RSSI, SIM ICCID/IMEI/IMSI)
      * /TMI/v1/network/configuration/v2?get=all (2.4GHz / 5GHz SSID & radio config)
      * /TMI/v1/gateway/reset?set=reboot (remote gateway reboot)
    """
    result: Dict[str, Any] = {"ip": ip, "action": action, "authenticated": False}
    try:
        gw_req = urllib.request.Request(f"http://{ip}/TMI/v1/gateway?get=all", headers={"User-Agent": "NetPulse/3.5"})
        with urllib.request.urlopen(gw_req, timeout=2.5) as r:
            result["gateway_all"] = json.loads(r.read(65536).decode("utf-8", errors="ignore"))
    except Exception as e:
        result["gateway_error"] = str(e)

    if not password:
        result["ok"] = "gateway_all" in result
        result["note"] = "Unauthenticated /TMI/v1/gateway?get=all fetched. Supply admin password to unlock /TMI/v1/network/telemetry?get=all or reboot."
        return result

    # Authenticate against POST /TMI/v1/auth/login
    try:
        login_payload = json.dumps({"username": username or "admin", "password": password}).encode("utf-8")
        login_req = urllib.request.Request(
            f"http://{ip}/TMI/v1/auth/login",
            data=login_payload,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "NetPulse/3.5"},
        )
        with urllib.request.urlopen(login_req, timeout=3.0) as r:
            auth_data = json.loads(r.read(16384).decode("utf-8", errors="ignore"))
        token = auth_data.get("auth", {}).get("token", "")
        if not token:
            result["ok"] = False
            result["auth_response"] = auth_data
            return result

        result["authenticated"] = True
        auth_headers = {"Authorization": f"Bearer {token}", "User-Agent": "NetPulse/3.5"}

        if action == "reboot":
            reb_req = urllib.request.Request(
                f"http://{ip}/TMI/v1/gateway/reset?set=reboot",
                data=b"",
                method="POST",
                headers=auth_headers,
            )
            with urllib.request.urlopen(reb_req, timeout=4.0) as r:
                result["reboot_response"] = json.loads(r.read(16384).decode("utf-8", errors="ignore"))
            result["ok"] = True
            return result

        for key, ep in [
            ("network_telemetry", "/TMI/v1/network/telemetry?get=all"),
            ("wifi_config", "/TMI/v1/network/configuration/v2?get=all"),
        ]:
            try:
                ep_req = urllib.request.Request(f"http://{ip}{ep}", headers=auth_headers)
                with urllib.request.urlopen(ep_req, timeout=3.0) as r:
                    result[key] = json.loads(r.read(65536).decode("utf-8", errors="ignore"))
            except Exception as sub_e:
                result[f"{key}_error"] = str(sub_e)

        result["ok"] = True
        return result
    except urllib.error.HTTPError as he:
        err_body = he.read(4096).decode("utf-8", errors="ignore")
        result["ok"] = False
        result["http_status"] = he.code
        result["error"] = err_body or str(he)
        return result
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
        return result


def control_bluetooth_device(mac: str = "", action: str = "info") -> Dict[str, Any]:
    """
    Active Bluetooth HCI / BlueZ controller via bluetoothctl:
    - 'info': Query full GATT/SDP UUID profiles, Modalias, RSSI, Paired/Connected status for a MAC.
    - 'scan': Run an active 4-second BLE + Classic inquiry scan and return discovered peripherals.
    - 'connect' / 'disconnect' / 'trust': Execute live BlueZ connection management.
    """
    clean_mac = mac.strip().upper()
    try:
        if action == "scan":
            subprocess.run(
                ["bluetoothctl", "--timeout", "4", "scan", "on"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=6,
            )
            devs = subprocess.check_output(["bluetoothctl", "devices"], text=True, timeout=3)
            return {"ok": True, "action": "scan", "devices_raw": devs.strip()}
        if not clean_mac:
            return {"ok": False, "error": "Bluetooth MAC address required"}
        cmd_Verb = action if action in ("info", "connect", "disconnect", "trust", "pair") else "info"
        out = subprocess.check_output(
            ["bluetoothctl", cmd_Verb, clean_mac],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=6,
        )
        return {"ok": True, "mac": clean_mac, "action": cmd_Verb, "output": out.strip()}
    except subprocess.CalledProcessError as cpe:
        return {"ok": False, "mac": clean_mac, "action": action, "output": (cpe.output or "").strip(), "error": str(cpe)}
    except Exception as e:
        return {"ok": False, "mac": clean_mac, "action": action, "error": str(e)}


def launch_local_client(ip: str, port: int = 80, protocol: str = "http", username: str = "") -> Dict[str, Any]:
    """
    Launch a native desktop session from this workstation to the target LAN device:
    - http / https: Opens URL in default desktop browser via xdg-open
    - ssh: Opens an interactive SSH terminal window on DISPLAY=:0
    - rdp: Launches xfreerdp / remmina / rdesktop to target IP:port
    """
    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")
    proto = protocol.lower().strip()
    try:
        if proto in ("http", "https"):
            scheme = "https" if (proto == "https" or port in (443, 8443)) else "http"
            url = f"{scheme}://{ip}:{port}/"
            subprocess.Popen(["xdg-open", url], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"ok": True, "launched": f"Opened browser to {url}"}
        elif proto == "ssh":
            target = f"{username}@{ip}" if username else ip
            for term in (
                ["x-terminal-emulator", "-e", f"ssh -p {port} {target}"],
                ["gnome-terminal", "--", "ssh", "-p", str(port), target],
                ["xterm", "-e", f"ssh -p {port} {target}"],
            ):
                try:
                    subprocess.Popen(term, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return {"ok": True, "launched": f"Launched SSH terminal to {target}:{port}"}
                except FileNotFoundError:
                    continue
            return {"ok": False, "error": "No desktop terminal emulator found"}
        elif proto == "rdp":
            for rdp_cmd in (
                ["xfreerdp", f"/v:{ip}:{port}", "/dynamic-resolution", "/cert:ignore"],
                ["remmina", "-c", f"rdp://{ip}:{port}"],
            ):
                try:
                    subprocess.Popen(rdp_cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return {"ok": True, "launched": f"Launched RDP client to {ip}:{port}"}
                except FileNotFoundError:
                    continue
            return {"ok": False, "error": "Neither xfreerdp nor remmina is installed"}
        return {"ok": False, "error": f"Unsupported protocol '{protocol}'"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class PassiveWireSniffer:
    """
    Real-time link-layer broadcast/multicast & deep packet sniffer powered by tshark/dumpcap.
    Passively captures ARP, DHCP, mDNS, SSDP, NBNS, IGMP, DNS, HTTP Host, and TLS SNI packets
    on the wire without requiring root privileges (leverages wireshark group cap_net_raw/cap_net_admin).
    """

    def __init__(self, interface: str = "wlo1", max_packets: int = 250) -> None:
        self.interface = interface
        self.packets: Deque[Dict[str, Any]] = deque(maxlen=max_packets)
        self.passive_hosts: Dict[str, str] = {}  # IP -> MAC observed on wire
        self.dhcp_hostnames: Dict[str, str] = {}  # MAC -> DHCP Option 12 hostname
        self.host_traffic: Dict[str, Dict[str, Any]] = {}  # IP -> {packets, bytes, protocols, domains, last_info}
        self.arp_anomalies: List[Dict[str, Any]] = []  # Live L2 MAC-flip / ARP spoofing alerts
        self._rate_samples: Dict[str, Deque[Tuple[float, int]]] = {}  # IP -> deque of (ts, bytes)
        self.running = False
        self._proc: Optional[subprocess.Popen[str]] = None
        self._thread: Optional[threading.Thread] = None
        self._on_packet_cb: Optional[Callable[[Dict[str, Any]], None]] = None

    def get_host_bandwidth(self, ip: str) -> Dict[str, float]:
        now = time.time()
        win = self._rate_samples.get(ip)
        if not win:
            return {"rate_kbps": 0.0, "pps": 0.0}
        while win and now - win[0][0] > 10.0:
            win.popleft()
        total_b = sum(b for _, b in win)
        cnt = len(win)
        return {
            "rate_kbps": round((total_b / 1024.0) / 10.0, 2),
            "pps": round(cnt / 10.0, 2),
        }

    def start(self, on_packet: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        if self.running:
            return
        self._on_packet_cb = on_packet
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Terminate the tshark capture child and reap it so no zombie remains."""
        self.running = False
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass
            except Exception:
                pass

    def _run_loop(self) -> None:
        cmd = [
            "tshark",
            "-i", self.interface,
            "-l", "-n",
            "-Y", "arp or dhcp or mdns or ssdp or nbns or llmnr or igmp or dns or tls.handshake.type == 1 or http.request or (tcp.flags.syn == 1 and tcp.flags.ack == 0)",
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "frame.time_epoch",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
            "-e", "dhcp.option.hostname",
            "-e", "arp.src.proto_ipv4",
            "-e", "frame.len",
            "-e", "dns.qry.name",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "dhcp.option.request_list_item",
            "-e", "dhcp.option.vendor_class_id",
            "-e", "tls.handshake.ja3",
            "-e", "ip.ttl",
            "-e", "tcp.window_size_value",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if not self.running:
                    break
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 7:
                    continue
                ts_str, eth_src, eth_dst, ip_src, ip_dst, proto, info = parts[:7]
                dhcp_host = parts[7] if len(parts) > 7 else ""
                arp_ip = parts[8] if len(parts) > 8 else ""
                frame_len_str = parts[9] if len(parts) > 9 else "0"
                dns_qry = parts[10] if len(parts) > 10 else ""
                tls_sni = parts[11] if len(parts) > 11 else ""
                dhcp_opt55 = parts[12] if len(parts) > 12 else ""
                dhcp_vclass = parts[13] if len(parts) > 13 else ""
                tls_ja3 = parts[14] if len(parts) > 14 else ""
                ip_ttl = parts[15] if len(parts) > 15 else ""
                tcp_win = parts[16] if len(parts) > 16 else ""

                src_ip = ip_src.split(",")[0] if ip_src else (arp_ip.split(",")[0] if arp_ip else "")
                src_mac = eth_src.split(",")[0].upper() if eth_src else ""
                try:
                    pkt_bytes = int(frame_len_str.split(",")[0]) if frame_len_str else 0
                except Exception:
                    pkt_bytes = 0

                if src_ip and src_mac and src_ip != "0.0.0.0":
                    now_ts = time.time()
                    prev_mac = self.passive_hosts.get(src_ip)
                    if prev_mac and prev_mac != src_mac and prev_mac != "00:00:00:00:00:00":
                        self.arp_anomalies.insert(0, {
                            "timestamp": now_ts,
                            "time_str": time.strftime("%H:%M:%S"),
                            "ip": src_ip,
                            "previous_mac": prev_mac,
                            "new_mac": src_mac,
                            "alert": f"Layer-2 MAC flip on {src_ip}: {prev_mac} -> {src_mac}",
                        })
                        del self.arp_anomalies[25:]
                    self.passive_hosts[src_ip] = src_mac
                    rwin = self._rate_samples.setdefault(src_ip, deque(maxlen=600))
                    rwin.append((now_ts, pkt_bytes))
                    while rwin and now_ts - rwin[0][0] > 10.0:
                        rwin.popleft()
                    cur_kbps = round((sum(b for _, b in rwin) / 1024.0) / 10.0, 2)
                    cur_pps = round(len(rwin) / 10.0, 2)

                    ht = self.host_traffic.setdefault(src_ip, {
                        "ip": src_ip,
                        "mac": src_mac,
                        "packets": 0,
                        "bytes": 0,
                        "rate_kbps": 0.0,
                        "peak_kbps": 0.0,
                        "pps": 0.0,
                        "protocols": [],
                        "domains": [],
                        "domain_timeline": [],
                        "ja3_hashes": [],
                        "dhcp_opt55": "",
                        "dhcp_vendor_class": "",
                        "tcp_syn_signature": "",
                        "last_info": "",
                        "last_seen": "",
                    })
                    ht["packets"] += 1
                    ht["bytes"] = ht.get("bytes", 0) + pkt_bytes
                    ht["rate_kbps"] = cur_kbps
                    ht["peak_kbps"] = max(ht.get("peak_kbps", 0.0), cur_kbps)
                    ht["pps"] = cur_pps
                    if proto and proto not in ht["protocols"]:
                        ht["protocols"].append(proto)
                    for dom_raw in (dns_qry, tls_sni):
                        if dom_raw:
                            for d in dom_raw.split(","):
                                d_clean = d.strip()
                                if d_clean and d_clean not in ht.setdefault("domains", []) and len(ht["domains"]) < 25:
                                    ht["domains"].append(d_clean)
                                if d_clean:
                                    tl = ht.setdefault("domain_timeline", [])
                                    if not tl or tl[0].get("domain") != d_clean:
                                        tl.insert(0, {
                                            "time": time.strftime("%H:%M:%S"),
                                            "domain": d_clean,
                                            "proto": "TLS SNI" if tls_sni else "DNS",
                                            "ja3": tls_ja3.split(",")[0] if tls_ja3 else "",
                                        })
                                        del tl[15:]
                    if tls_ja3:
                        for jh in tls_ja3.split(","):
                            jh_c = jh.strip()
                            if jh_c and jh_c not in ht.setdefault("ja3_hashes", []) and len(ht["ja3_hashes"]) < 10:
                                ht["ja3_hashes"].append(jh_c)
                    if dhcp_opt55:
                        ht["dhcp_opt55"] = dhcp_opt55
                    if dhcp_vclass:
                        ht["dhcp_vendor_class"] = dhcp_vclass
                    if ip_ttl and tcp_win:
                        ht["tcp_syn_signature"] = f"TTL={ip_ttl.split(',')[0]} WIN={tcp_win.split(',')[0]}"
                    ht["last_info"] = info[:100] if info else ""
                    ht["last_seen"] = time.strftime("%H:%M:%S")
                if dhcp_host and src_mac:
                    self.dhcp_hostnames[src_mac] = dhcp_host

                pkt = {
                    "timestamp": float(ts_str) if ts_str else time.time(),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(float(ts_str) if ts_str else time.time())),
                    "eth_src": src_mac,
                    "eth_dst": eth_dst.split(",")[0].upper() if eth_dst else "",
                    "ip_src": src_ip,
                    "ip_dst": ip_dst.split(",")[0] if ip_dst else "",
                    "protocol": proto or "L2",
                    "bytes": pkt_bytes,
                    "domain": tls_sni or dns_qry or "",
                    "ja3": tls_ja3.split(",")[0] if tls_ja3 else "",
                    "info": info[:160] if info else "",
                    "dhcp_hostname": dhcp_host,
                }
                self.packets.appendleft(pkt)
                if self._on_packet_cb:
                    try:
                        self._on_packet_cb(pkt)
                    except Exception:
                        pass
        except Exception:
            pass


# =============================================================================
# EXPANDED SMART HOME, ENTERPRISE SNMP & ACTIVE COUNTERMEASURES ENGINE
# =============================================================================

APPLE_HAP_CATEGORIES: Dict[str, str] = {
    "1": "Other HomeKit Accessory",
    "2": "HomeKit Bridge / Hub",
    "3": "Smart Fan",
    "4": "Garage Door Opener",
    "5": "Smart Lightbulb",
    "6": "Smart Door Lock",
    "7": "Smart Outlet / Plug",
    "8": "Smart Switch",
    "9": "Smart Thermostat",
    "10": "Environmental Sensor",
    "11": "Home Security System",
    "12": "Smart Door",
    "13": "Smart Window",
    "14": "Window Covering / Shade",
    "15": "Programmable Switch",
    "17": "HomeKit IP Camera",
    "18": "Video Doorbell",
    "19": "Air Purifier",
    "20": "Smart Heater",
    "21": "Air Conditioner",
    "22": "Humidifier",
    "23": "Dehumidifier",
    "24": "Apple TV",
    "26": "HomePod / Smart Speaker",
    "28": "Smart Sprinkler",
    "29": "Smart Faucet",
    "30": "Shower System",
    "31": "Smart Television",
    "32": "Target Remote Controller",
}


def probe_google_cast_eureka(
    ip: str,
    open_ports: List[int],
    mdns_services: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Decode Google Cast / Chromecast / Nest / Android TV devices via:
    1. _googlecast._tcp mDNS TXT records (md, fn, rs, st, ca, id, rm)
    2. HTTP :8008/setup/eureka_info JSON endpoint
    """
    result: Dict[str, Any] = {}
    for svc in mdns_services:
        stype = svc.get("service_type", "").lower()
        if "googlecast" in stype or "androidtvremote" in stype:
            txt = svc.get("txt", {})
            if txt.get("md"):
                result["model"] = txt["md"]
            if txt.get("fn"):
                result["friendly_name"] = txt["fn"]
            if txt.get("rs"):
                result["active_app"] = txt["rs"]
            if txt.get("id"):
                result["cast_uuid"] = txt["id"]
            if txt.get("rm"):
                result["relayed_mac"] = txt["rm"]
            result["mdns_service"] = stype

    if 8008 in open_ports or 8443 in open_ports or result:
        try:
            req = urllib.request.Request(
                f"http://{ip}:8008/setup/eureka_info?params=version,audio,name,build_info,detail,device_info,net,wifi,setup,settings&options=detail",
                headers={"User-Agent": "NetPulse/4.5"},
            )
            with urllib.request.urlopen(req, timeout=1.2) as r:
                data = json.loads(r.read(32768).decode("utf-8", errors="ignore"))
                if isinstance(data, dict):
                    if data.get("name"):
                        result["friendly_name"] = data["name"]
                    if data.get("build_version"):
                        result["firmware"] = data["build_version"]
                    dev_info = data.get("device_info", {})
                    if dev_info.get("model_name"):
                        result["model"] = dev_info["model_name"]
                    if dev_info.get("manufacturer"):
                        result["manufacturer"] = dev_info["manufacturer"]
                    if data.get("ssdp_udn"):
                        result["udn"] = data["ssdp_udn"]
        except Exception:
            pass

    return result if result else None


def probe_homekit_and_matter(
    ip: str,
    open_ports: List[int],
    mdns_services: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Decode Apple HomeKit (_hap._tcp) & CSA Matter / Thread (_matter._tcp, _matterc._udp, _meshcop._udp)
    smart home endpoints.
    """
    result: Dict[str, Any] = {}
    hap_port: Optional[int] = None
    for svc in mdns_services:
        stype = svc.get("service_type", "").lower()
        txt = svc.get("txt", {})
        if "_hap." in stype:
            result["ecosystem"] = "Apple HomeKit (HAP)"
            hap_port = svc.get("port")
            if txt.get("md"):
                result["model"] = txt["md"]
            if txt.get("pv"):
                result["protocol_version"] = txt["pv"]
            if txt.get("id"):
                result["pairing_id"] = txt["id"]
            if txt.get("c#"):
                result["config_number"] = txt["c#"]
            if txt.get("s#"):
                result["state_number"] = txt["s#"]
            if txt.get("ci"):
                result["category_name"] = APPLE_HAP_CATEGORIES.get(str(txt["ci"]), f"HAP Category {txt['ci']}")
            sf = txt.get("sf", "0")
            result["pairing_status"] = "Unpaired (Setup Mode)" if sf != "0" else "Paired & Encrypted"
        elif "_matter" in stype or "_meshcop" in stype:
            result["ecosystem"] = "Matter / Thread Smart Home"
            if txt.get("VP"):
                result["vendor_product_id"] = txt["VP"]
            if txt.get("NN"):
                result["thread_network_name"] = txt["NN"]

    if hap_port and hap_port in open_ports:
        result["hap_port"] = hap_port

    return result if result else None


def probe_snmp_sysinfo(ip: str, community: str = "public", timeout: float = 0.7) -> Optional[Dict[str, Any]]:
    """
    Send a pure ASN.1 BER SNMPv2c GetRequest (UDP 161) for MIB-II sysDescr.0 (1.3.6.1.2.1.1.1.0)
    and sysName.0 (1.3.6.1.2.1.1.5.0) and decode printable ASCII strings from the response.
    """
    comm_bytes = community.encode("ascii", errors="ignore")
    # OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) -> 2b 06 01 02 01 01 01 00
    # OID 1.3.6.1.2.1.1.5.0 (sysName.0)  -> 2b 06 01 02 01 01 05 00
    varbind_1 = bytes.fromhex("300c06082b060102010101000500")
    varbind_2 = bytes.fromhex("300c06082b060102010105000500")
    varbind_list = b"\x30" + bytes([len(varbind_1) + len(varbind_2)]) + varbind_1 + varbind_2
    # GetRequest-PDU (0xA0): req-id=1, err=0, err-idx=0
    pdu_hdr = bytes.fromhex("020101020100020100")
    pdu = b"\xa0" + bytes([len(pdu_hdr) + len(varbind_list)]) + pdu_hdr + varbind_list
    # SNMPv2c message: version=1 (v2c), community
    ver = bytes.fromhex("020101")
    comm = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
    body = ver + comm + pdu
    pkt = b"\x30" + bytes([len(body)]) + body

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (ip, 161))
        data, _ = sock.recvfrom(2048)
        # Extract OCTET STRING (0x04) values after OID 2b 06 01 02 01 01
        res: Dict[str, Any] = {"snmp_community": community}
        idx1 = data.find(bytes.fromhex("2b06010201010100"))
        if idx1 != -1 and idx1 + 10 < len(data):
            tag = data[idx1 + 8]
            length = data[idx1 + 9]
            if tag == 0x04 and idx1 + 10 + length <= len(data):
                res["sysDescr"] = data[idx1 + 10 : idx1 + 10 + length].decode("utf-8", errors="ignore").strip()
        idx5 = data.find(bytes.fromhex("2b06010201010500"))
        if idx5 != -1 and idx5 + 10 < len(data):
            tag = data[idx5 + 8]
            length = data[idx5 + 9]
            if tag == 0x04 and idx5 + 10 + length <= len(data):
                res["sysName"] = data[idx5 + 10 : idx5 + 10 + length].decode("utf-8", errors="ignore").strip()
        if "sysDescr" in res or "sysName" in res:
            return res
    except Exception:
        pass
    finally:
        sock.close()
    return None


def _kasa_xor_encrypt(plaintext: str) -> bytes:
    raw = plaintext.encode("utf-8")
    out = bytearray(struct.pack(">I", len(raw)))
    key = 171
    for b in raw:
        enc = key ^ b
        key = enc
        out.append(enc)
    return bytes(out)


def _kasa_xor_decrypt(ciphertext: bytes) -> str:
    if len(ciphertext) <= 4:
        return ""
    key = 171
    out = bytearray()
    for b in ciphertext[4:]:
        dec = key ^ b
        key = b
        out.append(dec)
    return out.decode("utf-8", errors="ignore")


def probe_smart_iot_and_tv(ip: str, open_ports: List[int]) -> Dict[str, Any]:
    """
    Deep prober for:
    - TP-Link Kasa Smart Plugs / Switches (TCP 9999 Autokey XOR protocol)
    - Shelly Gen1/Gen2/Gen3 Smart Relays & Power Meters (HTTP :80 /shelly, /rpc/Shelly.GetDeviceInfo)
    - Sonos ZonePlayer Smart Speakers (:1400/xml/device_description.xml)
    - Samsung Tizen Smart TV (:8001/api/v2/)
    """
    info: Dict[str, Any] = {}

    # 1. TP-Link Kasa Smart Plug (TCP 9999)
    if 9999 in open_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            s.connect((ip, 9999))
            s.sendall(_kasa_xor_encrypt('{"system":{"get_sysinfo":{}}}'))
            resp = s.recv(4096)
            dec = _kasa_xor_decrypt(resp)
            if dec:
                j = json.loads(dec)
                sysinfo = j.get("system", {}).get("get_sysinfo", {})
                if sysinfo:
                    info["protocol"] = "kasa"
                    info["model"] = sysinfo.get("model", "TP-Link Kasa Smart Plug")
                    info["alias"] = sysinfo.get("alias", "")
                    info["relay_state"] = "ON" if sysinfo.get("relay_state") == 1 else "OFF"
                    info["sw_ver"] = sysinfo.get("sw_ver", "")
        except Exception:
            pass
        finally:
            s.close()

    # 2. Shelly Smart Relay (HTTP 80)
    if 80 in open_ports and not info:
        for path in ("/shelly", "/rpc/Shelly.GetDeviceInfo"):
            try:
                req = urllib.request.Request(f"http://{ip}{path}", headers={"User-Agent": "NetPulse/4.5"})
                with urllib.request.urlopen(req, timeout=0.9) as r:
                    data = json.loads(r.read(8192).decode("utf-8", errors="ignore"))
                    if isinstance(data, dict) and ("mac" in data or "model" in data or "app" in data):
                        info["protocol"] = "shelly"
                        info["model"] = data.get("model") or data.get("type") or data.get("app") or "Shelly Smart Relay"
                        info["firmware"] = data.get("fw_id") or data.get("fw") or data.get("ver") or ""
                        break
            except Exception:
                pass

    # 3. Samsung Tizen TV (:8001/api/v2/)
    if 8001 in open_ports or 8002 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:8001/api/v2/", headers={"User-Agent": "NetPulse/4.5"})
            with urllib.request.urlopen(req, timeout=1.0) as r:
                data = json.loads(r.read(16384).decode("utf-8", errors="ignore"))
                dev = data.get("device", {})
                if dev:
                    info["protocol"] = "samsung_tizen"
                    info["model"] = dev.get("modelName") or dev.get("name") or "Samsung Smart TV"
                    info["friendly_name"] = data.get("name") or dev.get("name") or ""
                    info["os"] = dev.get("OS", "Tizen")
                    info["resolution"] = dev.get("resolution", "")
        except Exception:
            pass

    return info


def control_smart_home_device(ip: str, protocol: str, action: str = "status") -> Dict[str, Any]:
    """
    Execute real LAN control commands against TP-Link Kasa (TCP 9999), Shelly Relays (HTTP :80),
    or Google Cast / Samsung Tizen endpoints.
    """
    proto = protocol.lower().strip()
    act = action.lower().strip()
    try:
        if proto == "kasa":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                s.connect((ip, 9999))
                if act in ("on", "off"):
                    state_val = 1 if act == "on" else 0
                    cmd = json.dumps({"system": {"set_relay_state": {"state": state_val}}})
                elif act == "reboot":
                    cmd = '{"system":{"reboot":{"delay":1}}}'
                else:
                    cmd = '{"system":{"get_sysinfo":{}}}'
                s.sendall(_kasa_xor_encrypt(cmd))
                dec = _kasa_xor_decrypt(s.recv(4096))
                return {"ok": True, "ip": ip, "protocol": proto, "action": act, "response": json.loads(dec) if dec else {}}
            finally:
                s.close()
        elif proto == "shelly":
            if act in ("on", "off", "toggle"):
                url = f"http://{ip}/relay/0?turn={act}"
            else:
                url = f"http://{ip}/shelly"
            req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/4.5"})
            with urllib.request.urlopen(req, timeout=2.0) as r:
                return {"ok": True, "ip": ip, "protocol": proto, "action": act, "response": json.loads(r.read(8192).decode("utf-8", errors="ignore"))}
        elif proto == "google_cast":
            if act == "reboot":
                req = urllib.request.Request(
                    f"http://{ip}:8008/setup/reboot",
                    data=b'{"params":"now"}',
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=2.0) as r:
                    return {"ok": True, "ip": ip, "protocol": proto, "action": act, "http_status": r.status}
            info = probe_google_cast_eureka(ip, [8008], [])
            return {"ok": bool(info), "ip": ip, "protocol": proto, "action": act, "eureka_info": info or {}}
        return {"ok": False, "error": f"Unsupported smart-home protocol '{protocol}'"}
    except Exception as e:
        return {"ok": False, "ip": ip, "protocol": proto, "action": act, "error": str(e)}


def _parse_ssh_kexinit_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse an RFC 4253 binary SSH_MSG_KEXINIT (0x14 = 20) payload into its 10 algorithm
    name-lists, compute the Salesforce HASSH Server MD5 fingerprint, and grade crypto posture.
    """
    if len(payload) < 22 or payload[0] != 20:
        return None
    # Byte 0 is SSH_MSG_KEXINIT (20), bytes 1..17 are the 16-byte random cookie
    offset = 17
    lists: List[List[str]] = []
    for _ in range(10):
        if offset + 4 > len(payload):
            break
        nlen = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4
        if offset + nlen > len(payload):
            break
        raw_str = payload[offset : offset + nlen].decode("ascii", errors="ignore")
        offset += nlen
        lists.append([x for x in raw_str.split(",") if x])

    if len(lists) < 8:
        return None

    kex_algs = lists[0]
    host_key_algs = lists[1]
    enc_c2s = lists[2]
    enc_s2c = lists[3]
    mac_c2s = lists[4]
    mac_s2c = lists[5]
    cmp_c2s = lists[6]
    cmp_s2c = lists[7]

    # HASSH Server fingerprint: md5(kex_algorithms;encryption_s2c;mac_s2c;compression_s2c)
    hassh_raw = f"{','.join(kex_algs)};{','.join(enc_s2c)};{','.join(mac_s2c)};{','.join(cmp_s2c)}"
    hassh_server = hashlib.md5(hassh_raw.encode("utf-8")).hexdigest()

    weak_kex = [k for k in kex_algs if "group1-" in k or "sha1" in k]
    weak_ciphers = [c for c in enc_s2c if "cbc" in c or "arcfour" in c or "3des" in c or "des" in c]
    weak_hostkeys = [h for h in host_key_algs if h in ("ssh-dss", "ssh-rsa")]
    has_pqc = any("sntrup761" in k or "mlkem" in k for k in kex_algs)

    if not weak_kex and not weak_ciphers and has_pqc:
        grade = "A+ (Post-Quantum Hybrid KEX)"
    elif not weak_kex and not weak_ciphers:
        grade = "A (Modern AEAD / Elliptic Curve)"
    elif weak_ciphers or "diffie-hellman-group1-sha1" in weak_kex:
        grade = "C (Legacy CBC / SHA-1 KEX Enabled)"
    else:
        grade = "B (Transitional SHA-1 KEX Present)"

    return {
        "hassh_server": hassh_server,
        "crypto_grade": grade,
        "post_quantum_kex": has_pqc,
        "kex_algorithms": kex_algs[:12],
        "host_key_algorithms": host_key_algs[:10],
        "encryption_c2s": enc_c2s[:10],
        "encryption_s2c": enc_s2c[:10],
        "mac_c2s": mac_c2s[:10],
        "mac_s2c": mac_s2c[:10],
        "compression_c2s": cmp_c2s[:6],
        "compression_s2c": cmp_s2c[:6],
        "weak_kex": weak_kex,
        "weak_ciphers": weak_ciphers,
        "weak_hostkeys": weak_hostkeys,
    }


def probe_ssh_kex_and_hostkeys(ip: str, port: int = 22, timeout: float = 1.4) -> Optional[Dict[str, Any]]:
    """
    Perform an RFC 4253 SSHv2 protocol version exchange and binary SSH_MSG_KEXINIT
    inspection on TCP `port` to extract HASSH server fingerprint, post-quantum KEX support,
    host key types, and cipher weaknesses.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        banner_bytes = s.recv(256)
        banner_line = banner_bytes.splitlines()[0].decode("utf-8", errors="ignore").strip() if banner_bytes else ""
        if not banner_line.startswith("SSH-"):
            return None

        s.sendall(b"SSH-2.0-NetPulse_OmniSight_5.0\r\n")

        # If the first recv already contained the binary packet after the banner newline, preserve remainder
        nl_idx = banner_bytes.find(b"\n")
        buf = banner_bytes[nl_idx + 1 :] if nl_idx != -1 else b""
        while len(buf) < 16:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk

        if len(buf) >= 6:
            pkt_len = struct.unpack(">I", buf[:4])[0]
            pad_len = buf[4]
            while len(buf) < 4 + pkt_len and len(buf) < 16384:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            payload_len = pkt_len - pad_len - 1
            if payload_len > 0 and 5 + payload_len <= len(buf):
                payload = buf[5 : 5 + payload_len]
                parsed = _parse_ssh_kexinit_payload(payload)
                if parsed:
                    parsed["banner"] = banner_line
                    parsed["port"] = port
                    return parsed

        return {"banner": banner_line, "port": port, "crypto_grade": "Banner Only"}
    except Exception:
        return None
    finally:
        s.close()


def _build_smb2_negotiate_packet() -> bytes:
    """
    Construct a pure-binary NetBIOS Session Service + SMB2 NEGOTIATE request packet
    advertising dialects 0x0202 (2.0.2), 0x0210 (2.1), 0x0300 (3.0), 0x0302 (3.0.2), 0x0311 (3.1.1).
    """
    smb2_header = (
        b"\xfeSMB"                  # ProtocolId
        + struct.pack("<H", 64)     # StructureSize = 64
        + struct.pack("<H", 0)      # CreditCharge = 0
        + struct.pack("<I", 0)      # Status = 0
        + struct.pack("<H", 0)      # Command = SMB2_NEGOTIATE (0x0000)
        + struct.pack("<H", 31)     # CreditRequest = 31
        + struct.pack("<I", 0)      # Flags = 0
        + struct.pack("<I", 0)      # NextCommand = 0
        + struct.pack("<Q", 1)      # MessageId = 1
        + struct.pack("<I", 0)      # Reserved / ProcessId
        + struct.pack("<I", 0)      # TreeId
        + struct.pack("<Q", 0)      # SessionId
        + (b"\x00" * 16)            # Signature
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    client_guid = uuid.uuid4().bytes
    neg_body = (
        struct.pack("<H", 36)                   # StructureSize = 36
        + struct.pack("<H", len(dialects))      # DialectCount = 4
        + struct.pack("<H", 1)                  # SecurityMode = Signing Enabled (1)
        + struct.pack("<H", 0)                  # Reserved
        + struct.pack("<I", 0x7F)               # Capabilities
        + client_guid                           # ClientGuid (16 bytes)
        + struct.pack("<Q", 0)                  # NegotiateContextOffset/Count/Reserved
        + b"".join(struct.pack("<H", d) for d in dialects)
    )
    smb_payload = smb2_header + neg_body
    netbios_hdr = b"\x00" + struct.pack(">I", len(smb_payload))[1:]
    return netbios_hdr + smb_payload


SMB2_DIALECT_NAMES: Dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x02FF: "SMB 2.x Wildcard",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}


def _parse_smb2_negotiate_response(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a binary NetBIOS + SMB2 NEGOTIATE response packet to extract dialect revision,
    SMB signing enforcement (NTLM relay vulnerability status), Server GUID, and capabilities.
    """
    idx = data.find(b"\xfeSMB")
    if idx == -1 or len(data) < idx + 64 + 36:
        return None
    hdr = data[idx : idx + 64]
    cmd = struct.unpack("<H", hdr[12:14])[0]
    if cmd != 0:
        return None
    body = data[idx + 64 :]
    struct_sz = struct.unpack("<H", body[0:2])[0]
    if struct_sz != 65 or len(body) < 36:
        return None

    sec_mode = struct.unpack("<H", body[2:4])[0]
    dialect_rev = struct.unpack("<H", body[4:6])[0]
    server_guid_raw = body[8:24]
    caps = struct.unpack("<I", body[24:28])[0]

    signing_enabled = bool(sec_mode & 0x01)
    signing_required = bool(sec_mode & 0x02)
    try:
        srv_uuid = str(uuid.UUID(bytes_le=server_guid_raw))
    except Exception:
        srv_uuid = server_guid_raw.hex()

    cap_flags: List[str] = []
    for bit, name in [
        (0x01, "DFS"),
        (0x02, "LEASING"),
        (0x04, "LARGE_MTU"),
        (0x08, "MULTI_CHANNEL"),
        (0x10, "PERSISTENT_HANDLES"),
        (0x20, "DIRECTORY_LEASING"),
        (0x40, "ENCRYPTION"),
    ]:
        if caps & bit:
            cap_flags.append(name)

    return {
        "dialect": SMB2_DIALECT_NAMES.get(dialect_rev, f"SMB (0x{dialect_rev:04X})"),
        "dialect_code": f"0x{dialect_rev:04X}",
        "dialect_name": SMB2_DIALECT_NAMES.get(dialect_rev, f"SMB (0x{dialect_rev:04X})"),
        "security_mode": sec_mode,
        "signing_enabled": signing_enabled,
        "signing_required": signing_required,
        "ntlm_relay_vulnerable": not signing_required,
        "security_posture": "HARDENED (Signing Required)" if signing_required else "VULNERABLE (Signing Not Required — NTLM Relay Risk)",
        "server_guid": srv_uuid,
        "capabilities": cap_flags,
    }


def probe_smb2_negotiate(ip: str, port: int = 445, timeout: float = 1.4) -> Optional[Dict[str, Any]]:
    """
    Execute a binary SMB2/SMB3 NEGOTIATE handshake on TCP 445 and audit SMB signing & dialect.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(_build_smb2_negotiate_packet())
        resp = bytearray()
        while len(resp) < 128:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp.extend(chunk)
            if len(resp) >= 4:
                expected_len = struct.unpack(">I", b"\x00" + bytes(resp[1:4]))[0] + 4
                if len(resp) >= expected_len:
                    break
        parsed = _parse_smb2_negotiate_response(bytes(resp))
        if parsed:
            parsed["ip"] = ip
            parsed["port"] = port
            return parsed
    except Exception:
        pass
    finally:
        s.close()
    return None


def probe_mqtt_broker(ip: str, port: int = 1883, timeout: float = 0.9) -> Optional[Dict[str, Any]]:
    """
    Send a binary OASIS MQTT v3.1.1 CONNECT packet to TCP 1883 and inspect the 4-byte CONNACK
    to determine whether the IoT MQTT broker allows unauthenticated anonymous connections.
    """
    # Variable header: Protocol Name "MQTT" (00 04 4D 51 54 54), Level 4 (04), Flags CleanSession (02), KeepAlive 30s (00 1E)
    # Payload: ClientId "np5-probe" (00 09 6E 70 35 2D 70 72 6F 62 65)
    var_hdr = b"\x00\x04MQTT\x04\x02\x00\x1e"
    payload = b"\x00\x09np5-probe"
    rem_len = len(var_hdr) + len(payload)
    pkt = bytes([0x10, rem_len]) + var_hdr + payload

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(pkt)
        # Robust CONNACK read: loop until 4 bytes (fixed header 2 + variable 2).
        resp = b""
        while len(resp) < 4:
            chunk = s.recv(16)
            if not chunk:
                break
            resp += chunk
        # Disconnect cleanly
        try:
            s.sendall(b"\xe0\x00")
        except Exception:
            pass
        if len(resp) >= 4 and resp[0] == 0x20:
            # OASIS MQTT 3.1.1 CONNACK:
            # Byte 0: Packet Type (0x20 = CONNACK)
            # Byte 1: Remaining Length (0x02 bytes follow)
            # Byte 2: Connect Acknowledge Flags (bit 0 = Session Present)
            # Byte 3: Connect Return Code (0x00 = Connection Accepted, 0x05 = Not Authorized)
            ret_code = resp[3]
            anon_ok = ret_code == 0x00
            return {
                "port": port,
                "protocol": "MQTT v3.1.1",
                "connack_code": ret_code,
                "anonymous_allowed": anon_ok,
                "status": "CRITICAL: Anonymous Unauthenticated Access Allowed" if anon_ok else f"Authenticated Broker (CONNACK 0x{ret_code:02X})",
            }
    except Exception:
        pass
    finally:
        s.close()
    return None


def probe_extended_iot_and_infra(ip: str, open_ports: List[int]) -> Dict[str, Any]:
    """
    Deep protocol inspection for:
    - Sonos ZonePlayer Smart Speakers (:1400/xml/device_description.xml)
    - Philips Hue Smart Lighting Bridge (:80/api/config)
    - Plex Media Server (:32400/identity)
    - Ollama Local AI LLM Server (:11434/api/tags)
    - Docker Engine API (:2375/version)
    - OASIS MQTT Broker (:1883)
    """
    ext: Dict[str, Any] = {}

    # 1. Sonos ZonePlayer (:1400)
    if 1400 in open_ports:
        try:
            req = urllib.request.Request(
                f"http://{ip}:1400/xml/device_description.xml",
                headers={"User-Agent": "NetPulse/5.0"},
            )
            with urllib.request.urlopen(req, timeout=1.2) as r:
                xml_bytes = r.read(65536)
            root = ET.fromstring(xml_bytes)
            sonos: Dict[str, str] = {"protocol": "sonos"}
            for elem in root.iter():
                tag = _strip_xml_ns(elem.tag)
                val = (elem.text or "").strip()
                if tag in ("roomName", "displayName", "modelName", "modelNumber", "softwareVersion", "hardwareVersion", "serialNum", "MACAddress", "swGen") and val:
                    sonos[tag] = val
            if sonos.get("roomName") or sonos.get("modelName"):
                if "softwareVersion" in sonos:
                    sonos["software_version"] = sonos["softwareVersion"]
                if "serialNum" in sonos:
                    sonos["serial_num"] = sonos["serialNum"]
                if "roomName" in sonos:
                    sonos["room_name"] = sonos["roomName"]
                if "modelName" in sonos:
                    sonos["model"] = sonos["modelName"]
                if "modelNumber" in sonos:
                    sonos["model_number"] = sonos["modelNumber"]
                ext["sonos"] = sonos
        except Exception:
            pass

    # 2. Philips Hue Bridge (:80/api/config)
    if 80 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}/api/config", headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=0.9) as r:
                data = json.loads(r.read(16384).decode("utf-8", errors="ignore"))
                if isinstance(data, dict) and data.get("bridgeid") and data.get("modelid"):
                    ext["philips_hue"] = {
                        "name": data.get("name", "Philips Hue Bridge"),
                        "modelid": data.get("modelid", "BSB002"),
                        "bridgeid": data.get("bridgeid", ""),
                        "swversion": data.get("swversion", ""),
                        "apiversion": data.get("apiversion", ""),
                    }
        except Exception:
            pass

    # 3. Ollama AI Server (:11434/api/tags)
    if 11434 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:11434/api/tags", headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=1.0) as r:
                data = json.loads(r.read(32768).decode("utf-8", errors="ignore"))
                models = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict) and m.get("name")]
                ext["ollama_ai"] = {"models": models[:12], "model_count": len(models)}
        except Exception:
            pass

    # 4. Plex Media Server (:32400/identity)
    if 32400 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:32400/identity", headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=1.0) as r:
                xml_txt = r.read(16384).decode("utf-8", errors="ignore")
                m_ver = re.search(r'version="([^"]+)"', xml_txt)
                m_id = re.search(r'machineIdentifier="([^"]+)"', xml_txt)
                mid = m_id.group(1) if m_id else ""
                ext["plex"] = {
                    "version": m_ver.group(1) if m_ver else "Active",
                    "machine_id": mid,
                    "machine_identifier": mid,
                }
        except Exception:
            pass

    # 5. Unauthenticated Docker Engine API (:2375/version)
    if 2375 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:2375/version", headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=1.0) as r:
                data = json.loads(r.read(16384).decode("utf-8", errors="ignore"))
                if isinstance(data, dict) and data.get("Version"):
                    ext["docker_api"] = {
                        "version": data.get("Version"),
                        "api_version": data.get("ApiVersion"),
                        "os": data.get("Os"),
                        "arch": data.get("Arch"),
                    }
        except Exception:
            pass

    # 6. MQTT IoT Broker (:1883)
    if 1883 in open_ports:
        mqtt_res = probe_mqtt_broker(ip, 1883)
        if mqtt_res:
            ext["mqtt"] = mqtt_res

    return ext


def control_sonos_speaker(ip: str, action: str = "status", volume: Optional[int] = None) -> Dict[str, Any]:
    """
    Control a Sonos ZonePlayer over LAN UPnP SOAP (TCP 1400):
    Supports 'play', 'pause', 'stop', 'next', 'previous', 'status', and 'volume'.
    """
    act = action.lower().strip()
    try:
        if act == "volume" and volume is not None:
            vol_clamped = max(0, min(100, int(volume)))
            soap_body = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                "<s:Body>"
                '<u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1">'
                "<InstanceID>0</InstanceID><Channel>Master</Channel>"
                f"<DesiredVolume>{vol_clamped}</DesiredVolume>"
                "</u:SetVolume>"
                "</s:Body></s:Envelope>"
            ).encode("utf-8")
            req = urllib.request.Request(
                f"http://{ip}:1400/MediaRenderer/RenderingControl/Control",
                data=soap_body,
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": '"urn:schemas-upnp-org:service:RenderingControl:1#SetVolume"',
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return {"ok": resp.status == 200, "ip": ip, "action": f"SetVolume({vol_clamped})"}

        soap_cmd_map = {
            "play": "Play",
            "pause": "Pause",
            "stop": "Stop",
            "next": "Next",
            "previous": "Previous",
            "status": "GetTransportInfo",
        }
        soap_verb = soap_cmd_map.get(act, "GetTransportInfo")
        extra_tag = "<Speed>1</Speed>" if soap_verb == "Play" else ""
        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            f'<u:{soap_verb} xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">'
            f"<InstanceID>0</InstanceID>{extra_tag}"
            f"</u:{soap_verb}>"
            "</s:Body></s:Envelope>"
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://{ip}:1400/MediaRenderer/AVTransport/Control",
            data=soap_body,
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"urn:schemas-upnp-org:service:AVTransport:1#{soap_verb}"',
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            raw_xml = resp.read(8192).decode("utf-8", errors="ignore")
            m_state = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", raw_xml)
            return {
                "ok": resp.status == 200,
                "ip": ip,
                "action": soap_verb,
                "transport_state": m_state.group(1) if m_state else "OK",
            }
    except Exception as e:
        return {"ok": False, "ip": ip, "action": act, "error": str(e)}


def probe_upnp_igd_nat_mappings(gateway_ip: str, upnp_location: str = "", timeout: float = 1.8) -> Dict[str, Any]:
    """
    Query the gateway router's UPnP InternetGatewayDevice (WANIPConnection:1 / WANPPPConnection:1)
    SOAP interface to enumerate active external NAT port-forwarding rules.
    """
    result: Dict[str, Any] = {
        "gateway_ip": gateway_ip,
        "igd_found": False,
        "control_url": "",
        "external_ip": "",
        "port_mappings": [],
    }
    candidate_locs: List[str] = []
    if upnp_location:
        candidate_locs.append(upnp_location)

    # Probe gateway directly via unicast SSDP for WANIPConnection:1 if no location known
    if not candidate_locs:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.6)
        try:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\n"
                "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n"
            ).encode("ascii")
            s.sendto(msg, (gateway_ip, 1900))
            s.sendto(msg, ("239.255.255.250", 1900))
            data, _ = s.recvfrom(4096)
            for ln in data.decode("utf-8", errors="ignore").splitlines():
                if ln.lower().startswith("location:"):
                    loc = ln.split(":", 1)[1].strip()
                    if loc:
                        candidate_locs.append(loc)
        except Exception:
            pass
        finally:
            s.close()

    control_url = ""
    service_type = "urn:schemas-upnp-org:service:WANIPConnection:1"
    for loc in candidate_locs:
        try:
            req = urllib.request.Request(loc, headers={"User-Agent": "NetPulse/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                xml_bytes = r.read(65536)
            root = ET.fromstring(xml_bytes)
            for elem in root.iter():
                if _strip_xml_ns(elem.tag) == "service":
                    st = ""
                    cu = ""
                    for ch in elem:
                        ctag = _strip_xml_ns(ch.tag)
                        if ctag == "serviceType" and ch.text:
                            st = ch.text.strip()
                        elif ctag == "controlURL" and ch.text:
                            cu = ch.text.strip()
                    if ("WANIPConnection" in st or "WANPPPConnection" in st) and cu:
                        service_type = st
                        control_url = urllib.parse.urljoin(loc, cu)
                        break
            if control_url:
                break
        except Exception:
            continue

    if not control_url:
        return result

    result["igd_found"] = True
    result["control_url"] = control_url

    # Query GetExternalIPAddress
    try:
        soap_ext = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:GetExternalIPAddress xmlns:u="{service_type}"></u:GetExternalIPAddress></s:Body>'
            "</s:Envelope>"
        ).encode("utf-8")
        req = urllib.request.Request(
            control_url,
            data=soap_ext,
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service_type}#GetExternalIPAddress"',
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read(8192).decode("utf-8", errors="ignore")
            m_ip = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", txt)
            if m_ip:
                result["external_ip"] = m_ip.group(1).strip()
    except Exception:
        pass

    # Enumerate up to 16 active UPnP port mappings via GetGenericPortMappingEntry
    for idx in range(16):
        try:
            soap_map = (
                '<?xml version="1.0"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
                f"<NewPortMappingIndex>{idx}</NewPortMappingIndex>"
                "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
            ).encode("utf-8")
            req = urllib.request.Request(
                control_url,
                data=soap_map,
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"',
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=1.0) as r:
                txt = r.read(8192).decode("utf-8", errors="ignore")
                ext_p = re.search(r"<NewExternalPort>([^<]+)</NewExternalPort>", txt)
                int_p = re.search(r"<NewInternalPort>([^<]+)</NewInternalPort>", txt)
                int_c = re.search(r"<NewInternalClient>([^<]+)</NewInternalClient>", txt)
                proto = re.search(r"<NewProtocol>([^<]+)</NewProtocol>", txt)
                desc = re.search(r"<NewPortMappingDescription>([^<]*)</NewPortMappingDescription>", txt)
                if ext_p and int_c:
                    result["port_mappings"].append({
                        "index": idx,
                        "protocol": proto.group(1).strip() if proto else "TCP",
                        "external_port": int(ext_p.group(1).strip()),
                        "internal_client": int_c.group(1).strip(),
                        "internal_port": int(int_p.group(1).strip()) if int_p else 0,
                        "description": desc.group(1).strip() if desc else "",
                    })
        except Exception:
            break

    return result


def _build_dnssec_query_packet(
    qname: str = "cloudflare.com",
    qtype: int = 1,
    qclass: int = 1,
    enable_do: bool = True,
    txid: int = 0x4E50,
) -> bytes:
    """
    Construct a pure-binary RFC 1035 DNS Query packet with optional RFC 4035 EDNS0 (OPT RR 41)
    and DNSSEC OK (DO=1, 0x8000) + Checking Disabled (CD=0) flags.
    """
    arcount = 1 if enable_do else 0
    hdr = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0120, 1, 0, 0, arcount)
    labels = b"".join(
        struct.pack("B", len(lbl)) + lbl.encode("ascii")
        for lbl in qname.strip(".").split(".")
        if lbl
    ) + b"\x00"
    question = labels + struct.pack(">HH", qtype, qclass)
    if not enable_do:
        return hdr + question
    # RFC 6891 EDNS0 OPT RR: NAME=0x00 (1B), TYPE=41 (2B), CLASS=4096 (2B), TTL=0x00008000 (DO=1, 4B), RDLEN=0 (2B)
    opt_rr = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    return hdr + question + opt_rr


def _parse_dns_response_header(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a binary RFC 1035 DNS response header to extract RCODE, Recursion Available (RA),
    Authenticated Data (AD — RFC 4035 DNSSEC verified), Truncated (TC), and answer counts.
    """
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    qr = bool(flags & 0x8000)
    if not qr:
        return None
    aa = bool(flags & 0x0400)
    tc = bool(flags & 0x0200)
    rd = bool(flags & 0x0100)
    ra = bool(flags & 0x0080)
    ad = bool(flags & 0x0020)
    cd = bool(flags & 0x0010)
    rcode = flags & 0x000F
    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
    return {
        "txid": f"0x{txid:04X}",
        "rcode": rcode,
        "rcode_name": rcode_names.get(rcode, f"RCODE_{rcode}"),
        "recursion_available": ra,
        "dnssec_ad_verified": ad,
        "authoritative": aa,
        "truncated": tc,
        "recursion_desired": rd,
        "checking_disabled": cd,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
    }


def probe_dns_security_posture(ip: str, timeout: float = 1.2) -> Dict[str, Any]:
    """
    Audit a DNS resolver (gateway or server on port 53 / 853) for:
    1. RFC 4035 DNSSEC signature validation (`AD=1` flag on signed domain `cloudflare.com`)
    2. Recursive resolver capability (`RA=1`) and query resolution latency (`ms`)
    3. Chaos class (`CH TXT version.bind`) resolver version disclosure
    4. RFC 7858 DNS-over-TLS (`TCP 853`) encrypted transport availability
    """
    res: Dict[str, Any] = {
        "ip": ip,
        "dns_active": False,
        "recursion_available": False,
        "dnssec_validated": False,
        "dot_port_853_open": False,
        "dot_tls_cipher": "",
        "version_bind_leak": "",
        "query_rtt_ms": None,
        "rcode_name": "NO_RESPONSE",
        "security_grade": "N/A",
    }

    pkt = _build_dnssec_query_packet("cloudflare.com", qtype=1, qclass=1, enable_do=True, txid=0x4E51)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        sock.sendto(pkt, (ip, 53))
        data, _ = sock.recvfrom(4096)
        rtt = round((time.perf_counter() - t0) * 1000.0, 2)
        parsed = _parse_dns_response_header(data)
        if parsed:
            res["dns_active"] = True
            res["query_rtt_ms"] = rtt
            res["recursion_available"] = parsed["recursion_available"]
            res["dnssec_validated"] = parsed["dnssec_ad_verified"]
            res["rcode_name"] = parsed["rcode_name"]
            res["answer_count"] = parsed["answer_count"]
    except Exception:
        pass
    finally:
        sock.close()

    if res["dns_active"]:
        ch_pkt = _build_dnssec_query_packet("version.bind", qtype=16, qclass=3, enable_do=False, txid=0x4E52)
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.settimeout(0.7)
        try:
            csock.sendto(ch_pkt, (ip, 53))
            cdata, _ = csock.recvfrom(1024)
            cparsed = _parse_dns_response_header(cdata)
            if cparsed and cparsed["rcode"] == 0 and cparsed["answer_count"] > 0 and len(cdata) > 30:
                tail_ascii = "".join(chr(b) if 32 <= b <= 126 else " " for b in cdata[28:]).strip()
                parts = [p.strip() for p in tail_ascii.split("  ") if len(p.strip()) >= 3]
                if parts:
                    res["version_bind_leak"] = parts[-1][:64]
        except Exception:
            pass
        finally:
            csock.close()

    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tsock.settimeout(0.9)
    try:
        if tsock.connect_ex((ip, 853)) == 0:
            res["dot_port_853_open"] = True
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(tsock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    res["dot_tls_cipher"] = f"{cipher[0]} ({cipher[1]})"
    except Exception:
        pass
    finally:
        try:
            tsock.close()
        except Exception:
            pass

    if not res["dns_active"] and not res["dot_port_853_open"]:
        res["security_grade"] = "Inactive (Port 53/853 Closed)"
    elif res["dnssec_validated"] and res["dot_port_853_open"]:
        res["security_grade"] = "A+ (DNSSEC Validating + DoT 853 Encrypted)"
    elif res["dnssec_validated"] and not res["version_bind_leak"]:
        res["security_grade"] = "A (DNSSEC Validating Resolver)"
    elif res["dns_active"] and not res["version_bind_leak"]:
        res["security_grade"] = "B (Recursive Resolver — DNSSEC AD=0)"
    else:
        res["security_grade"] = "C (Resolver Version Leakage / Unvalidated)"

    return res


NTP_DELTA_1900_TO_1970 = 2208988800


def _parse_ntp_packet(data: bytes, client_tx_ts: float = 0.0, client_rx_ts: float = 0.0) -> Optional[Dict[str, Any]]:
    """
    Parse a 48-byte binary RFC 5905 NTPv3/v4 server response packet (`!BBBbIIIQQQQ`)
    to extract Stratum, Reference Clock ID (`ref_id`), Root Delay/Dispersion, and clock offset.
    """
    if len(data) < 48:
        return None
    li_vn_mode, stratum, poll, precision, root_delay_raw, root_disp_raw, ref_id_raw = struct.unpack(
        "!BBBbIII", data[:16]
    )
    vn = (li_vn_mode >> 3) & 0x07
    mode = li_vn_mode & 0x07
    if mode not in (4, 5):  # 4 = Server, 5 = Broadcast
        return None

    root_delay_ms = round((root_delay_raw / 65536.0) * 1000.0, 3)
    root_disp_ms = round((root_disp_raw / 65536.0) * 1000.0, 3)

    ref_bytes = data[12:16]
    if stratum in (0, 1):
        ref_id_str = "".join(chr(b) if 32 <= b <= 126 else "" for b in ref_bytes).strip() or f"0x{ref_id_raw:08X}"
    else:
        ref_id_str = socket.inet_ntoa(ref_bytes)

    # Unpack Transmit Timestamp (bytes 40..48)
    tx_sec, tx_frac = struct.unpack("!II", data[40:48])
    rx_sec, rx_frac = struct.unpack("!II", data[32:40])
    server_tx_epoch = (tx_sec - NTP_DELTA_1900_TO_1970) + (tx_frac / 4294967296.0) if tx_sec > NTP_DELTA_1900_TO_1970 else 0.0
    server_rx_epoch = (rx_sec - NTP_DELTA_1900_TO_1970) + (rx_frac / 4294967296.0) if rx_sec > NTP_DELTA_1900_TO_1970 else 0.0

    offset_ms = 0.0
    if client_tx_ts > 0 and client_rx_ts > 0 and server_tx_epoch > 0 and server_rx_epoch > 0:
        offset_ms = round((((server_rx_epoch - client_tx_ts) + (server_tx_epoch - client_rx_ts)) / 2.0) * 1000.0, 2)

    return {
        "ntp_version": vn,
        "stratum": stratum,
        "poll_interval_log2": poll,
        "precision_log2": precision,
        "root_delay_ms": root_delay_ms,
        "root_dispersion_ms": root_disp_ms,
        "ref_id": ref_id_str,
        "server_tx_epoch": round(server_tx_epoch, 3),
        "clock_offset_ms": offset_ms,
    }


def probe_ntp_server(ip: str, timeout: float = 1.1) -> Dict[str, Any]:
    """
    Send a 48-byte binary RFC 5905 NTPv4 Client request (`0x23` + 47 zero bytes) to UDP 123
    and test for NTP Mode 6 Control/Amplification exposure.
    """
    res: Dict[str, Any] = {
        "ip": ip,
        "ntp_active": False,
        "stratum": None,
        "ref_id": "",
        "root_delay_ms": None,
        "root_dispersion_ms": None,
        "clock_offset_ms": None,
        "rtt_ms": None,
        "mode6_control_exposed": False,
    }
    pkt = b"\x23" + (b"\x00" * 47)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        p0 = time.perf_counter()
        s.sendto(pkt, (ip, 123))
        data, _ = s.recvfrom(512)
        t1 = time.time()
        rtt = round((time.perf_counter() - p0) * 1000.0, 2)
        parsed = _parse_ntp_packet(data, client_tx_ts=t0, client_rx_ts=t1)
        if parsed:
            res.update(parsed)
            res["ntp_active"] = True
            res["rtt_ms"] = rtt
    except Exception:
        pass
    finally:
        s.close()

    # Check NTP Mode 6 Read Status / Read Variables exposure (0x16 = VN 2, Mode 6 Control; Op 2 = Read Variables)
    if res["ntp_active"]:
        m6_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        m6_sock.settimeout(0.6)
        try:
            m6_pkt = b"\x16\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            m6_sock.sendto(m6_pkt, (ip, 123))
            m6_resp, _ = m6_sock.recvfrom(1024)
            if len(m6_resp) >= 12 and (m6_resp[0] & 0x07) == 6:
                res["mode6_control_exposed"] = True
        except Exception:
            pass
        finally:
            m6_sock.close()

    return res


def audit_ipv6_posture(interface: str = "wlo1") -> Dict[str, Any]:
    """
    Audit the active interface's IPv6 Dual-Stack configuration, RFC 8981 Temporary Privacy
    Addresses, ICMPv6 Neighbor Discovery cache, and active IPv6 Router Advertisements (RA).
    """
    posture: Dict[str, Any] = {
        "interface": interface,
        "ipv6_enabled": False,
        "global_unicast_addresses": [],
        "link_local_addresses": [],
        "privacy_extensions_active": False,
        "default_ipv6_gateway": "",
        "ipv6_routers": [],
        "ipv6_neighbors_count": 0,
        "rogue_ra_detected": False,
        "security_grade": "IPv6 Disabled / Link-Local Only",
    }
    try:
        addr_out = subprocess.check_output(["ip", "-6", "-j", "addr", "show", "dev", interface], text=True, timeout=2.0)
        for iface_obj in json.loads(addr_out):
            for a in iface_obj.get("addr_info", []):
                if a.get("family") != "inet6":
                    continue
                local_v6 = a.get("local", "")
                scope = a.get("scope", "")
                posture["ipv6_enabled"] = True
                if scope == "global":
                    posture["global_unicast_addresses"].append(local_v6)
                    if a.get("temporary") or a.get("mngtmpaddr"):
                        posture["privacy_extensions_active"] = True
                elif scope == "link":
                    posture["link_local_addresses"].append(local_v6)
    except Exception:
        pass

    try:
        rt_out = subprocess.check_output(["ip", "-6", "-j", "route", "show", "dev", interface], text=True, timeout=2.0)
        for rt in json.loads(rt_out):
            if rt.get("dst") == "default" and rt.get("gateway"):
                posture["default_ipv6_gateway"] = rt["gateway"]
                break
    except Exception:
        pass

    try:
        neigh_out = subprocess.check_output(["ip", "-6", "-j", "neigh", "show", "dev", interface], text=True, timeout=2.0)
        neigh_list = json.loads(neigh_out)
        posture["ipv6_neighbors_count"] = len(neigh_list)
        router_macs: Set[str] = set()
        for n in neigh_list:
            if n.get("router"):
                lladdr = (n.get("lladdr") or "").upper()
                dst_v6 = n.get("dst", "")
                intel = oui_db.lookup(lladdr) if lladdr else None
                eui = unmask_eui64_ipv6_mac([dst_v6])
                if lladdr:
                    mac_prefix5 = ":".join(lladdr.split(":")[:5]) if lladdr.count(":") == 5 else lladdr
                    router_macs.add(mac_prefix5)  # Group by 5-octet silicon prefix
                posture["ipv6_routers"].append({
                    "ipv6": dst_v6,
                    "mac": lladdr,
                    "vendor": intel.vendor if intel else "Unknown",
                    "eui64_unmasked_mac": eui[0] if eui else "",
                    "state": ",".join(n.get("state", [])) if isinstance(n.get("state"), list) else str(n.get("state", "")),
                })
        if len(router_macs) > 1:
            posture["rogue_ra_detected"] = True
    except Exception:
        pass

    if posture["rogue_ra_detected"]:
        posture["security_grade"] = "F (Multiple Conflicting IPv6 Routers / Rogue RA Risk)"
    elif posture["global_unicast_addresses"] and posture["privacy_extensions_active"]:
        posture["security_grade"] = "A+ (Dual-Stack Global IPv6 + RFC 8981 Privacy Extensions)"
    elif posture["global_unicast_addresses"]:
        posture["security_grade"] = "B (Global IPv6 Active — Static/EUI-64 Interface ID)"
    elif posture["ipv6_enabled"]:
        posture["security_grade"] = "A (Link-Local IPv6 Only — No WAN v6 Exposure)"

    return posture


def send_port_knock_sequence(
    ip: str,
    ports: List[int],
    protocol: str = "tcp",
    delay_ms: int = 75,
    verify_port: int = 22,
) -> Dict[str, Any]:
    """
    Transmit a deterministic multi-port TCP SYN or UDP port-knocking sequence to `ip`
    and check whether `verify_port` is open following the sequence.
    """
    clean_ports = [int(p) for p in ports if 1 <= int(p) <= 65535][:12]
    proto = protocol.lower().strip()
    steps: List[Dict[str, Any]] = []
    for idx, p in enumerate(clean_ports):
        t0 = time.perf_counter()
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(b"NP_KNOCK", (ip, p))
            except Exception:
                pass
            finally:
                s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.12)
            try:
                s.connect_ex((ip, p))
            except Exception:
                pass
            finally:
                s.close()
        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        steps.append({"step": idx + 1, "port": p, "protocol": proto.upper(), "elapsed_ms": elapsed})
        if idx < len(clean_ports) - 1 and delay_ms > 0:
            time.sleep(min(0.5, delay_ms / 1000.0))

    verify_open = False
    if 1 <= verify_port <= 65535:
        vs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        vs.settimeout(0.35)
        try:
            verify_open = vs.connect_ex((ip, verify_port)) == 0
        except Exception:
            pass
        finally:
            vs.close()

    return {
        "ok": True,
        "ip": ip,
        "sequence": clean_ports,
        "protocol": proto.upper(),
        "steps": steps,
        "verify_port": verify_port,
        "verify_port_open": verify_open,
    }


class HostQuarantineManager:
    """
    Active Guardian Shield Host Quarantine, Dynamic TCP RST Teardown & Gateway MAC Lock Engine.
    Maintains an active enforcement loop against quarantined/intruder LAN IPs,
    dispatching connection-reset probes across all open + standard ports and guarding the
    default gateway against Layer-2 ARP cache poisoning.
    """

    def __init__(self) -> None:
        self.quarantined: Dict[str, Dict[str, Any]] = {}
        self.locked_gateway_ip: str = ""
        self.locked_gateway_mac: str = ""
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.running = False

    def lock_gateway_mac(self, gateway_ip: str, gateway_mac: str) -> Dict[str, Any]:
        with self._lock:
            self.locked_gateway_ip = gateway_ip.strip()
            self.locked_gateway_mac = gateway_mac.strip().upper()
            return {
                "gateway_ip": self.locked_gateway_ip,
                "locked_mac": self.locked_gateway_mac,
                "locked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def verify_gateway_mac(self, gateway_ip: str, current_mac: str) -> Dict[str, Any]:
        clean_cur = current_mac.strip().upper()
        with self._lock:
            if not self.locked_gateway_mac and clean_cur and clean_cur != "00:00:00:00:00:00":
                self.locked_gateway_ip = gateway_ip.strip()
                self.locked_gateway_mac = clean_cur
            spoofed = bool(
                self.locked_gateway_mac
                and clean_cur
                and clean_cur != "00:00:00:00:00:00"
                and clean_cur != self.locked_gateway_mac
            )
            return {
                "gateway_ip": gateway_ip,
                "locked_mac": self.locked_gateway_mac,
                "locked_gateway_mac": self.locked_gateway_mac,
                "current_mac": clean_cur,
                "observed_mac": clean_cur,
                "arp_spoof_detected": spoofed,
                "spoof_detected": spoofed,
                "alert": (
                    f"CRITICAL ARP SPOOFING: Gateway {gateway_ip} MAC changed from locked {self.locked_gateway_mac} to {clean_cur}!"
                    if spoofed
                    else ""
                ),
            }

    def _set_firewall_drop(self, ip: str, drop: bool) -> Dict[str, Any]:
        """Best-effort L3 drop via iptables/nftables. Returns backend + result; never raises."""
        import shutil as _sh
        actions: List[str] = []
        backend = "rst-only"
        for tool in ("iptables", "nft"):
            if _sh.which(tool):
                backend = tool
                try:
                    if tool == "iptables":
                        for chain in ("FORWARD", "INPUT"):
                            if drop:
                                exists = subprocess.run(["iptables", "-C", chain, "-s", ip, "-j", "DROP"], capture_output=True, timeout=2.0)
                                if exists.returncode == 0:
                                    actions.append(f"iptables -C {chain} already present (skip)")
                                    continue
                                cmd_base = ["iptables", "-A", chain, "-s", ip, "-j", "DROP"]
                            else:
                                cmd_base = ["iptables", "-D", chain, "-s", ip, "-j", "DROP"]
                            r = subprocess.run(cmd_base, capture_output=True, timeout=2.0)
                            actions.append(f"{' '.join(cmd_base)} -> rc={r.returncode}")
                    else:  # nft
                        table = "netpulse_quarantine"
                        if drop:
                            subprocess.run(["nft", "add", "table", "ip", table], capture_output=True, timeout=2.0)
                            subprocess.run(["nft", "add", "chain", "ip", table, "fwd", "{ type filter hook forward priority 0; }"], capture_output=True, timeout=2.0)
                            r = subprocess.run(["nft", "add", "rule", "ip", table, "fwd", "ip", "saddr", ip, "drop"], capture_output=True, timeout=2.0)
                            actions.append(f"nft add rule saddr {ip} drop -> rc={r.returncode}")
                        else:
                            r = subprocess.run(["nft", "flush", "table", "ip", table], capture_output=True, timeout=2.0)
                            actions.append(f"nft flush table -> rc={r.returncode}")
                    return {"backend": backend, "actions": actions, "ok": True}
                except Exception as exc:
                    actions.append(str(exc)[:120])
                break
        return {"backend": backend, "actions": actions, "ok": False, "note": "no iptables/nft or insufficient privilege; RST loop fallback"}

    def engage(
        self,
        ip: str,
        mac: str = "",
        reason: str = "Operator Quarantine",
        target_ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        ports = sorted(set((target_ports or []) + [80, 443, 8080, 22, 445, 554, 3389, 8008, 8060]))
        fw = self._set_firewall_drop(ip, True)
        with self._lock:
            self.quarantined[ip] = {
                "ip": ip,
                "mac": mac.upper(),
                "reason": reason,
                "target_ports": ports,
                "engaged_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp": time.time(),
                "pulses_sent": 0,
                "firewall": fw,
            }
            if not self.running:
                self.running = True
                self._thread = threading.Thread(target=self._enforcement_loop, daemon=True)
                self._thread.start()
            return dict(self.quarantined[ip])

    def release(self, ip: str) -> bool:
        self._set_firewall_drop(ip, False)
        with self._lock:
            removed = self.quarantined.pop(ip, None) is not None
            if not self.quarantined:
                self.running = False
            return removed

    def is_quarantined(self, ip: str) -> bool:
        with self._lock:
            return ip in self.quarantined

    def list_quarantined(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.quarantined.values())

    def _enforcement_loop(self) -> None:
        while self.running:
            with self._lock:
                targets = [(ip, list(info.get("target_ports", [80, 443, 8080, 22, 445, 554]))) for ip, info in self.quarantined.items()]
            if not targets:
                break
            for tip, tports in targets:
                try:
                    for p in tports:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.08)
                        try:
                            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                            s.connect_ex((tip, p))
                        except Exception:
                            pass
                        finally:
                            s.close()
                    with self._lock:
                        if tip in self.quarantined:
                            self.quarantined[tip]["pulses_sent"] = self.quarantined[tip].get("pulses_sent", 0) + 1
                except Exception:
                    pass
            time.sleep(2.5)


quarantine_engine = HostQuarantineManager()


def calculate_subnet_cidr(cidr_str: str) -> Dict[str, Any]:
    """
    Calculate comprehensive IPv4/IPv6 CIDR subnet parameters: network address, broadcast,
    netmask, wildcard mask, usable host range, total usable hosts, IPv4 class, and RFC scope.
    """
    raw = (cidr_str or "192.168.12.0/24").strip()
    if "/" not in raw:
        raw = f"{raw}/24" if ":" not in raw else f"{raw}/64"
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except Exception as e:
        return {"ok": False, "query": cidr_str, "error": f"Invalid CIDR notation: {e}"}

    if isinstance(net, ipaddress.IPv4Network):
        num_addr = net.num_addresses
        usable = max(0, num_addr - 2) if net.prefixlen < 31 else num_addr
        first_usable = str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address)
        last_usable = str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address)
        b0 = net.network_address.packed[0]
        if b0 < 128:
            ip_class = "Class A"
        elif b0 < 192:
            ip_class = "Class B"
        elif b0 < 224:
            ip_class = "Class C"
        elif b0 < 240:
            ip_class = "Class D (Multicast)"
        else:
            ip_class = "Class E (Experimental)"

        if net.is_private:
            scope = "RFC 1918 Private LAN"
        elif net.is_loopback:
            scope = "RFC 1122 Loopback"
        elif net.is_link_local:
            scope = "RFC 3927 APIPA Link-Local"
        elif net.is_multicast:
            scope = "RFC 5771 Multicast"
        else:
            scope = "Public Routable WAN"

        return {
            "ok": True,
            "version": 4,
            "ip_version": 4,
            "cidr": str(net),
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address),
            "netmask": str(net.netmask),
            "wildcard_mask": str(net.hostmask),
            "hostmask": str(net.hostmask),
            "prefix_length": net.prefixlen,
            "total_addresses": num_addr,
            "usable_hosts": usable,
            "first_usable_ip": first_usable,
            "last_usable_ip": last_usable,
            "first_usable": first_usable,
            "last_usable": last_usable,
            "ip_class": ip_class,
            "scope": scope,
        }
    else:
        return {
            "ok": True,
            "version": 6,
            "ip_version": 6,
            "cidr": str(net),
            "network_address": str(net.network_address),
            "broadcast_address": "N/A (IPv6 Multicast)",
            "netmask": str(net.netmask),
            "wildcard_mask": str(net.hostmask),
            "hostmask": str(net.hostmask),
            "prefix_length": net.prefixlen,
            "total_addresses": net.num_addresses,
            "usable_hosts": net.num_addresses,
            "first_usable_ip": str(net.network_address),
            "last_usable_ip": str(net.broadcast_address),
            "first_usable": str(net.network_address),
            "last_usable": str(net.broadcast_address),
            "ip_class": "IPv6 128-bit",
            "scope": "RFC 4193 ULA / Link-Local" if net.is_private or net.is_link_local else "Global Unicast (2000::/3)",
        }


def audit_local_workstation_sockets() -> Dict[str, Any]:
    """
    Inspect the local scanner workstation's active listening TCP/UDP sockets (`ss -tulnpH`),
    established outbound connections (`ss -tupnH state established`), owning Linux processes,
    and `/proc/net/dev` interface byte/packet counters.
    """
    listening: List[Dict[str, Any]] = []
    established: List[Dict[str, Any]] = []
    iface_stats: List[Dict[str, Any]] = []

    try:
        out_l = subprocess.check_output(["ss", "-tulnpH"], text=True, timeout=2.5)
        for line in out_l.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].upper()
            local_ep = parts[4]
            proc_raw = " ".join(parts[6:]) if len(parts) > 6 else ""
            m_proc = re.search(r'"([^"]+)",pid=(\d+)', proc_raw)
            proc_name = m_proc.group(1) if m_proc else "kernel/system"
            pid = int(m_proc.group(2)) if m_proc else None
            # Split host:port
            if "]:" in local_ep:
                bind_addr, port_s = local_ep.rsplit(":", 1)
            elif ":" in local_ep:
                bind_addr, port_s = local_ep.rsplit(":", 1)
            else:
                bind_addr, port_s = local_ep, "0"
            bind_clean = bind_addr.split("%")[0]
            try:
                port_num = int(port_s)
            except Exception:
                port_num = 0
            is_exposed = bind_clean in ("0.0.0.0", "*", "[::]", "::")
            listening.append({
                "proto": proto,
                "protocol": proto,
                "bind_address": bind_addr,
                "port": port_num,
                "process": proc_name,
                "pid": pid,
                "scope": "LAN/Wildcard Exposed" if is_exposed else "Loopback / Local-Only",
                "lan_exposed": is_exposed,
            })
    except Exception:
        pass

    try:
        out_e = subprocess.check_output(["ss", "-tupnH", "state", "established"], text=True, timeout=2.5)
        for line in out_e.splitlines()[:40]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].upper()
            local_ep = parts[3] if len(parts) == 5 else parts[4]
            remote_ep = parts[4] if len(parts) == 5 else (parts[5] if len(parts) > 5 else "")
            proc_raw = " ".join(parts[5:])
            m_proc = re.search(r'"([^"]+)",pid=(\d+)', proc_raw)
            proc_name = m_proc.group(1) if m_proc else "user/system"
            pid = int(m_proc.group(2)) if m_proc else None
            established.append({
                "protocol": proto,
                "local": local_ep,
                "remote": remote_ep,
                "process": proc_name,
                "pid": pid,
            })
    except Exception:
        pass

    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            for line in f.read().splitlines()[2:]:
                if ":" not in line:
                    continue
                ifname, rest = line.split(":", 1)
                ifname = ifname.strip()
                cols = rest.split()
                if len(cols) >= 10:
                    rx_bytes = int(cols[0])
                    rx_pkts = int(cols[1])
                    tx_bytes = int(cols[8])
                    tx_pkts = int(cols[9])
                    iface_stats.append({
                        "interface": ifname,
                        "rx_mb": round(rx_bytes / (1024 * 1024), 2),
                        "tx_mb": round(tx_bytes / (1024 * 1024), 2),
                        "rx_packets": rx_pkts,
                        "tx_packets": tx_pkts,
                    })
    except Exception:
        pass

    listening.sort(key=lambda x: (not x["lan_exposed"], x["port"]))
    return {
        "ok": True,
        "hostname": socket.gethostname(),
        "listening_count": len(listening),
        "lan_exposed_count": sum(1 for x in listening if x["lan_exposed"]),
        "established_count": len(established),
        "listening_sockets": listening[:60],
        "established_connections": established[:40],
        "interface_counters": iface_stats,
    }


def _query_dns_txt_or_mx_via_dig_or_socket(domain: str, qtype_str: str) -> List[str]:
    """Query DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`) using `dig +short` or `getent`/`socket` fallback."""
    out_records: List[str] = []
    try:
        raw = subprocess.check_output(
            ["dig", "+time=1", "+tries=1", "+short", domain, qtype_str],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        for line in raw.splitlines():
            c = line.strip()
            if c and not c.startswith(";"):
                out_records.append(c)
        if out_records:
            return out_records[:40]
    except Exception:
        pass

    if qtype_str == "A":
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                ip = str(info[4][0])
                if ip not in out_records:
                    out_records.append(ip)
        except Exception:
            pass
    elif qtype_str == "AAAA":
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
                ip6 = str(info[4][0])
                if ip6 not in out_records:
                    out_records.append(ip6)
        except Exception:
            pass
    return out_records[:12]


def probe_domain_and_wan_target(target: str) -> Dict[str, Any]:
    """
    All-Around Domain, SSL/TLS X.509 Certificate Chain, HTTP/3 & Security Header,
    DNS Record (`A`, `AAAA`, `MX`, `NS`, `TXT`), Email Anti-Spoofing (`SPF`, `DMARC`),
    and Autonomous System (ASN) Reconnaissance Engine.
    """
    clean_t = (target or "cloudflare.com").strip()
    clean_t = re.sub(r"^https?://", "", clean_t).split("/")[0].split(":")[0].strip()
    if not clean_t:
        clean_t = "cloudflare.com"

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        f_a = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, clean_t, "A")
        f_aaaa = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, clean_t, "AAAA")
        f_mx = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, clean_t, "MX")
        f_ns = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, clean_t, "NS")
        f_txt = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, clean_t, "TXT")
        f_dmarc = ex.submit(_query_dns_txt_or_mx_via_dig_or_socket, f"_dmarc.{clean_t}", "TXT")

        a_recs = f_a.result()
        aaaa_recs = f_aaaa.result()
        mx_recs = f_mx.result()
        ns_recs = f_ns.result()
        txt_recs = f_txt.result()
        dmarc_recs = f_dmarc.result()

    primary_ip = a_recs[0] if a_recs else ""
    if not primary_ip:
        try:
            primary_ip = socket.gethostbyname(clean_t)
            if primary_ip:
                a_recs = [primary_ip]
        except Exception:
            pass

    if not (primary_ip or a_recs or aaaa_recs or ns_recs or mx_recs):
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return {
            "ok": False,
            "error": f"Failed to resolve host or DNS records for '{clean_t}'",
            "target": clean_t,
            "domain": clean_t,
            "primary_ipv4": "",
            "reverse_ptr": "",
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "spf_record": "",
            "spf_present": False,
            "dmarc_record": "",
            "dmarc_present": False,
            "security_score": 0,
            "security_grade": "F",
            "findings": ["Host does not resolve to any IPv4 or IPv6 address"],
            "elapsed_ms": elapsed_ms,
            "dns_records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SPF": "", "DMARC": "", "email_spoofing_posture": "UNRESOLVED"},
            "tls": {},
            "tls_certificate": {},
            "http": {},
            "https_posture": {},
        }

    spf_rec = next((t for t in txt_recs if "v=spf1" in t.lower()), "")
    dmarc_rec = next((d for d in dmarc_recs if "v=dmarc1" in d.lower()), "")
    if spf_rec and dmarc_rec:
        email_security = "HARDENED (SPF + DMARC Enforced)"
    elif spf_rec or dmarc_rec:
        email_security = "PARTIAL (Missing DMARC or SPF)"
    else:
        email_security = "UNPROTECTED (No SPF/DMARC Anti-Spoofing)"

    # Inspect TLS 443 & X.509 Certificate
    tls_info: Dict[str, Any] = {}
    if primary_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.2)
        try:
            p0 = time.perf_counter()
            s.connect((primary_ip, 443))
            tcp_rtt = round((time.perf_counter() - p0) * 1000.0, 2)
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(s, server_hostname=clean_t) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                subj = dict(x[0] for x in cert.get("subject", ())) if cert else {}
                issuer = dict(x[0] for x in cert.get("issuer", ())) if cert else {}
                sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"] if cert else []
                tls_info = {
                    "tcp_443_rtt_ms": tcp_rtt,
                    "tls_version": ssock.version() or "",
                    "protocol": ssock.version() or "",
                    "cipher_suite": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if (cipher and len(cipher) > 2) else 256,
                    "subject_cn": subj.get("commonName", clean_t),
                    "issuer_org": issuer.get("organizationName", "") or issuer.get("commonName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "not_before": cert.get("notBefore", "") if cert else "",
                    "not_after": cert.get("notAfter", "") if cert else "",
                    "san_domains": sans[:12],
                    "san_count": len(sans),
                    "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper() if der else "",
                }
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    # Inspect HTTPS headers & HTTP/3 Alt-Svc
    http_info: Dict[str, Any] = {}
    try:
        req = urllib.request.Request(
            f"https://{clean_t}/",
            headers={"User-Agent": "NetPulse-OmniSight/4.5"},
            method="HEAD",
        )
        h0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            ttfb = round((time.perf_counter() - h0) * 1000.0, 2)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            missing_sec = []
            sec_hdrs: Dict[str, str] = {}
            for req_h, label in [
                ("strict-transport-security", "HSTS"),
                ("content-security-policy", "CSP"),
                ("x-frame-options", "X-Frame-Options"),
                ("x-content-type-options", "X-Content-Type-Options"),
            ]:
                if req_h in hdrs:
                    sec_hdrs[req_h] = hdrs[req_h]
                else:
                    missing_sec.append(label)
            http3_ok = "h3" in hdrs.get("alt-svc", "")
            http_info = {
                "status_code": resp.status,
                "ttfb_ms": ttfb,
                "latency_ms": ttfb,
                "server": hdrs.get("server", ""),
                "alt_svc_http3": http3_ok,
                "http3_supported": http3_ok,
                "hsts": hdrs.get("strict-transport-security", ""),
                "security_headers": sec_hdrs,
                "missing_security_headers": missing_sec,
            }
    except Exception:
        pass

    reverse_ptr = ""
    if primary_ip:
        try:
            reverse_ptr = socket.gethostbyaddr(primary_ip)[0]
        except Exception:
            pass

    score = 50
    findings: List[str] = []
    if tls_info.get("protocol") == "TLSv1.3":
        score += 20
    elif tls_info.get("protocol"):
        score += 10
    else:
        findings.append("No TLS :443 listener detected")
    if spf_rec:
        score += 10
    else:
        findings.append("Missing SPF TXT record")
    if dmarc_rec:
        score += 10
    else:
        findings.append("Missing _dmarc TXT record")
    if http_info.get("hsts"):
        score += 5
    if http_info.get("http3_supported"):
        score += 5
    score = max(0, min(100, score))
    security_grade = "A+" if score >= 95 else ("A" if score >= 85 else ("B" if score >= 70 else "C"))

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    return {
        "ok": True,
        "target": clean_t,
        "domain": clean_t,
        "primary_ipv4": primary_ip,
        "reverse_ptr": reverse_ptr,
        "ipv4_addresses": a_recs,
        "ipv6_addresses": aaaa_recs,
        "mx_records": mx_recs,
        "ns_records": ns_recs,
        "txt_records": txt_recs[:8],
        "spf_record": spf_rec,
        "spf_present": bool(spf_rec),
        "dmarc_record": dmarc_rec,
        "dmarc_present": bool(dmarc_rec),
        "security_score": score,
        "security_grade": security_grade,
        "findings": findings,
        "elapsed_ms": elapsed_ms,
        "dns_records": {
            "A": a_recs,
            "AAAA": aaaa_recs,
            "MX": mx_recs,
            "NS": ns_recs,
            "TXT": txt_recs[:8],
            "SPF": spf_rec,
            "DMARC": dmarc_rec,
            "email_spoofing_posture": email_security,
        },
        "tls": tls_info,
        "tls_certificate": tls_info,
        "http": http_info,
        "https_posture": http_info,
    }


