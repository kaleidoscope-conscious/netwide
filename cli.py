"""
Rich Terminal CLI & Live TUI Guardian for NetPulse (OmniSight).
Commands:
  python3 -m netpulse scan                -> Instant multi-vector subnet scan & Rich device matrix
  python3 -m netpulse watch               -> Live auto-refreshing Terminal TUI Network Guardian
  python3 -m netpulse wifi                -> 2.4/5 GHz RF Spectrum & Co-Located Hidden SSID De-Cloaker
  python3 -m netpulse speedtest           -> Cloudflare Multi-Stream WAN Throughput & Jitter Test
  python3 -m netpulse wol <MAC>           -> Transmit IEEE 802 Wake-on-LAN Magic Packet
  python3 -m netpulse roku <IP> <KEY>     -> Send live Roku ECP remote keypress (Home, VolumeMute, FindRemote, etc.)
  python3 -m netpulse serve [--port 8765] -> Launch the Sovereign Web Command Center + WebSocket Daemon
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List

import uvicorn
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from netpulse.database import net_db
from netpulse.fingerprint import (
    DeviceProfile,
    audit_network_threats,
    compute_network_security_posture,
    run_full_network_scan,
)
from netpulse.oui import oui_db
from netpulse.probers import (
    audit_local_workstation_sockets,
    calculate_subnet_cidr,
    detect_active_interface,
    probe_domain_and_wan_target,
    send_roku_keypress,
    send_wake_on_lan,
)
from netpulse.wireless import fetch_wan_intelligence, run_wan_speedtest, scan_bluetooth_radar, wireless_engine

console = Console(width=145 if not sys.stdout.isatty() else None)


def build_device_table(profiles: List[DeviceProfile], title: str) -> Table:
    table = Table(title=title, show_lines=True, header_style="bold cyan", border_style="bright_blue")
    table.add_column("IPv4", style="bold bright_white", no_wrap=True)
    table.add_column("MAC / OUI Vendor", style="cyan")
    table.add_column("Identity / Model / Firmware", style="bold green")
    table.add_column("Category", style="magenta")
    table.add_column("Power / Active App", style="yellow")
    table.add_column("RTT / Method", justify="right", style="bright_cyan")
    table.add_column("Open Ports", style="white")
    table.add_column("Conf", justify="right", style="bold green")

    for p in profiles:
        ports_str = ", ".join(f":{ps['port']}({ps['service']})" for ps in p.port_services[:5]) or "Stealth"
        fw_str = f"\n[dim]FW: {p.firmware_version}[/dim]" if p.firmware_version else ""
        sec_mac = f"\n[dim]+{','.join(p.secondary_macs)}[/dim]" if p.secondary_macs else ""
        rtt_str = f"{p.rtt_ms} ms\n[dim]{p.rtt_method}[/dim]" if p.rtt_ms is not None else "ARP"
        table.add_row(
            p.ip,
            f"{p.mac}{sec_mac}\n[dim]{p.vendor[:28]}[/dim]",
            f"{p.custom_name or p.display_name}{fw_str}",
            p.category,
            p.power_state,
            rtt_str,
            ports_str,
            f"{p.confidence_score}%",
        )
    return table


def cmd_scan() -> None:
    t0 = time.perf_counter()
    net = detect_active_interface()
    console.print(
        Panel(
            f"[bold cyan]NETPULSE // OMNISIGHT v2.0[/bold cyan] — Active Interface [bold green]{net.interface}[/bold green] "
            f"([bold]{net.ip}[/bold] on [bold]{net.cidr}[/bold] • Gateway [bold]{net.gateway_ip}[/bold] • "
            f"SSID [bold yellow]{net.ssid}[/bold yellow] Ch {net.channel}) • "
            f"IEEE OUI Database: [bold]{oui_db.loaded_count:,}[/bold] prefixes",
            border_style="cyan",
        )
    )
    profiles = run_full_network_scan(net)
    net_db.sync_scan_results(profiles)
    dt = time.perf_counter() - t0

    table = build_device_table(
        profiles,
        f"Discovered {len(profiles)} Active LAN Hosts in {dt:.2f}s (ARP + mDNS + SSDP + Roku ECP + PS DDP + Spotify + 5G TMI)",
    )
    console.print(table)


def cmd_watch() -> None:
    net = detect_active_interface()
    cycle = 0
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            cycle += 1
            t0 = time.perf_counter()
            profiles = run_full_network_scan(net)
            net_db.sync_scan_results(profiles)
            dt = time.perf_counter() - t0
            tbl = build_device_table(
                profiles,
                f"LIVE GUARDIAN CYCLE #{cycle} • {len(profiles)} Hosts Online • Scan {dt:.2f}s • {time.strftime('%H:%M:%S')} (Ctrl+C to exit)",
            )
            live.update(tbl)
            time.sleep(10)


def cmd_wifi() -> None:
    wifi = wireless_engine.scan_wifi_spectrum(trigger_rescan=False)
    bt = scan_bluetooth_radar()
    tbl = Table(
        title=f"802.11 RF Spectrum & Co-Located Hidden SSID De-Cloaker ({wifi['total_aps']} BSSIDs)",
        show_lines=True,
        header_style="bold cyan",
    )
    tbl.add_column("SSID / De-Cloaked Radio", style="bold green")
    tbl.add_column("BSSID", style="cyan")
    tbl.add_column("Band / Ch", style="magenta")
    tbl.add_column("Signal / Est. Distance", style="yellow")
    tbl.add_column("Security", style="white")
    tbl.add_column("IEEE OUI Vendor", style="dim")

    for ap in wifi["access_points"]:
        ssid_txt = f"{'* ' if ap['in_use'] else ''}{ap['ssid']}"
        if ap["de_cloaked_parent"]:
            ssid_txt += f"\n[bold yellow]🔓 De-Cloaked: {ap['de_cloaked_parent']}[/bold yellow]"
        tbl.add_row(
            ssid_txt,
            ap["bssid"],
            f"{ap['band']} (Ch {ap['channel']})",
            f"{ap['signal_pct']}% ({ap['signal_dbm']} dBm • ~{ap['est_distance_m']}m)",
            ap["security"],
            ap["vendor"],
        )
    console.print(tbl)
    ch_rec = wifi.get("channel_recommendations", {})
    if ch_rec:
        b24 = ch_rec.get("band_24ghz", {})
        b5 = ch_rec.get("band_5ghz", {})
        console.print(
            Panel(
                f"[bold emerald]2.4 GHz Optimal Channel:[/bold emerald] Ch [bold]{b24.get('recommended_channel')}[/bold] "
                f"(Congestion {b24.get('congestion_score')}%) — {b24.get('rationale', '')}\n"
                f"[bold cyan]5 GHz Optimal Channel:[/bold cyan]   Ch [bold]{b5.get('recommended_channel')}[/bold] "
                f"(Congestion {b5.get('congestion_score')}%) — {b5.get('rationale', '')}",
                title="802.11 RF Spectral Interference & Channel Optimizer",
                border_style="cyan",
            )
        )
    ctrl = bt["controller"]
    console.print(
        Panel(
            f"[bold cyan]Bluetooth 5.2 HCI Radar:[/bold cyan] {ctrl['interface']} ({ctrl['bd_address']}) — "
            f"[green]{ctrl['status']}[/green] • {ctrl['manufacturer']} • "
            f"Discovered Targets: {', '.join(d['name'] + ' [' + d['mac'] + ']' for d in bt['devices']) or 'None'}",
            border_style="magenta",
        )
    )


def cmd_speedtest() -> None:
    console.print("[bold cyan][*] Executing Cloudflare Multi-Stream WAN Throughput, Upload & Bufferbloat Benchmark…[/bold cyan]")
    wan = fetch_wan_intelligence()
    res = run_wan_speedtest()
    console.print(
        Panel(
            f"[bold green]⚡ Download Throughput: {res['download_mbps']} Mbps[/bold green]  •  "
            f"[bold cyan]⬆ Upload Throughput: {res.get('upload_mbps', 0.0)} Mbps[/bold cyan]\n"
            f"Unloaded Ping: [bold]{res['unloaded_ping_ms']} ms[/bold] • "
            f"Loaded Ping: [bold]{res.get('loaded_ping_ms', 'N/A')} ms[/bold] • "
            f"Bufferbloat: [bold yellow]+{res.get('bufferbloat_delta_ms', 0.0)} ms ({res.get('bufferbloat_grade', 'A')})[/bold yellow] • "
            f"Jitter: [bold]{res['jitter_ms']} ms[/bold]\n"
            f"Transferred: {res['bytes_transferred'] / 1e6:.1f} MB down / {res.get('upload_bytes_transferred', 0) / 1e6:.1f} MB up in {res['duration_sec']}s\n"
            f"WAN Egress: [cyan]{wan['public_ip']}[/cyan] ({wan['isp']} • {wan['city']}, {wan['region']})",
            title="WAN Speedtest, Bufferbloat & Egress Telemetry",
            border_style="green",
        )
    )


def cmd_audit() -> None:
    net = detect_active_interface()
    profiles = run_full_network_scan(net)
    devices = net_db.sync_scan_results(profiles)
    wifi = wireless_engine.scan_wifi_spectrum(trigger_rescan=False, lan_devices=devices)
    threats = audit_network_threats(devices, wifi, net.ssid)
    posture = compute_network_security_posture(devices, threats, wifi)

    p_lines = [
        f"[bold bright_white]Subnet Security Score:[/bold bright_white] [bold green]{posture['score']}/100 (Grade {posture['grade']})[/bold green] "
        f"• Evaluated Hosts: [bold]{posture['online_hosts_evaluated']}[/bold] "
        f"• Critical Threats: [bold red]{posture['critical_threat_count']}[/bold red] "
        f"• High Threats: [bold yellow]{posture['high_threat_count']}[/bold yellow]"
    ]
    for _, p_info in posture.get("pillars", {}).items():
        p_lines.append(f"  • {p_info['label']}: [bold cyan]{p_info['score']}/{p_info['max']}[/bold cyan]")

    console.print(Panel("\n".join(p_lines), title="NETPULSE // Cryptographic & Security Posture Audit", border_style="cyan"))

    tbl = Table(title="Per-Host Cryptographic & Vulnerability Matrix", show_lines=True, header_style="bold cyan")
    tbl.add_column("IPv4 / Host", style="bold white")
    tbl.add_column("Risk", justify="right")
    tbl.add_column("SSHv2 HASSH / Grade", style="cyan")
    tbl.add_column("SMB2/3 & DNSSEC", style="magenta")
    tbl.add_column("Security Findings", style="yellow")

    for d in devices:
        ssh_i = d.get("ssh_info") or {}
        smb_i = d.get("smb_info") or {}
        dns_i = d.get("dns_info") or {}
        ssh_str = f"{ssh_i.get('crypto_grade', '—')}\n[dim]{ssh_i.get('hassh_server', '')}[/dim]" if ssh_i else "—"
        smb_parts = []
        if smb_i:
            smb_parts.append(f"{smb_i.get('dialect_name') or smb_i.get('dialect', 'SMB')} ({'Req' if smb_i.get('signing_required') else 'NTLM Relay Risk'})")
        if dns_i and (dns_i.get("dns_active") or dns_i.get("dot_port_853_open")):
            smb_parts.append(f"DNS: {dns_i.get('security_grade')} (AD={dns_i.get('dnssec_validated')})")
        smb_str = "\n".join(smb_parts) if smb_parts else "—"
        f_str = "\n".join(f"[{f.get('severity')}] {f.get('title')}" for f in (d.get("security_findings") or [])[:3])
        tbl.add_row(
            f"{d['ip']}\n[dim]{d.get('display_name', '')[:32]}[/dim]",
            str(d.get("risk_score", 0)),
            ssh_str,
            smb_str,
            f_str or "Hardened",
        )
    console.print(tbl)


def cmd_oui(query: str) -> None:
    res = oui_db.search(query, limit=30)
    tbl = Table(
        title=f"IEEE OUI Hardware & EUI-64 Intelligence Search: '{query}' (Mode: {res.get('mode')}, Matches: {res.get('total_matches')})",
        show_lines=True,
        header_style="bold cyan",
    )
    tbl.add_column("OUI Prefix / MAC", style="bold cyan")
    tbl.add_column("Manufacturer", style="bold green")
    tbl.add_column("Registry / Notes", style="yellow")
    tbl.add_column("Headquarters / Unmasked Info", style="white")

    for r in res.get("results", []):
        prefix = r.get("prefix") or r.get("oui_prefix") or r.get("mac") or ""
        vendor = r.get("vendor", "")
        reg = r.get("registry") or r.get("registry_type", "IEEE MA-L (24-bit)")
        hq = r.get("address") or r.get("vendor_address") or ""
        if r.get("unmasked_mac"):
            prefix = f"{r.get('ipv6', query)} -> {r['unmasked_mac']}"
        elif r.get("unmasked_parent_vendor"):
            hq += f" [Unmasked LAA Parent: {r['unmasked_parent_oui']} ({r['unmasked_parent_vendor']})]"
        tbl.add_row(prefix, vendor, reg, hq)
    console.print(tbl)


def cmd_domain(target: str) -> None:
    res = probe_domain_and_wan_target(target)
    if not res.get("ok"):
        console.print(f"[bold red]Domain probe failed:[/bold red] {res.get('error')}")
        return
    tls = res.get("tls") or {}
    http = res.get("http") or {}
    console.print(
        Panel(
            f"[bold cyan]Target Domain / Host:[/bold cyan] [bold white]{res.get('domain')}[/bold white] "
            f"(Grade [bold green]{res.get('security_grade')}[/bold green] • Score [bold]{res.get('security_score')}/100[/bold])\n"
            f"[bold yellow]IPv4 (A):[/bold yellow] {', '.join(res.get('ipv4_addresses') or ['—'])}  •  "
            f"[bold yellow]IPv6 (AAAA):[/bold yellow] {', '.join(res.get('ipv6_addresses') or ['—'])}\n"
            f"[bold magenta]PTR (rDNS):[/bold magenta] {res.get('reverse_ptr') or '—'}\n"
            f"[bold green]SPF Record:[/bold green] {res.get('spf_record') or 'Missing'}\n"
            f"[bold green]DMARC Record:[/bold green] {res.get('dmarc_record') or 'Missing'}\n"
            f"[bold cyan]TLS 443:[/bold cyan] {tls.get('protocol') or 'Closed'} • {tls.get('cipher_suite') or '—'} • "
            f"CN={tls.get('subject_cn') or '—'} (Issuer: {tls.get('issuer_org') or tls.get('issuer_cn') or '—'})\n"
            f"[bold cyan]HTTPS Status:[/bold cyan] {http.get('status_code') or '—'} • Server: {http.get('server') or '—'} • "
            f"Title: {http.get('title') or '—'} • HTTP/3: {http.get('http3_supported')}",
            title="All-Around Domain, DNS, Email Security & TLS Reconnaissance",
            border_style="cyan",
        )
    )


def cmd_sockets() -> None:
    res = audit_local_workstation_sockets()
    console.print(
        Panel(
            f"[bold cyan]Listening Daemons:[/bold cyan] [bold white]{res.get('listening_count')}[/bold white]  •  "
            f"[bold yellow]LAN-Exposed Services:[/bold yellow] [bold red]{res.get('lan_exposed_count')}[/bold red]  •  "
            f"[bold green]Established Connections:[/bold green] [bold white]{res.get('established_count')}[/bold white]",
            title="Local Workstation Socket, Port & Process Inspector",
            border_style="cyan",
        )
    )
    tbl = Table(title="Active Local Listening Ports (ss -tulnp)", show_lines=True, header_style="bold cyan")
    tbl.add_column("Proto", style="cyan")
    tbl.add_column("Bind Address : Port", style="bold white")
    tbl.add_column("Process / PID", style="bold green")
    tbl.add_column("Scope", style="yellow")
    for s in res.get("listening_sockets", [])[:35]:
        tbl.add_row(
            s.get("proto", ""),
            f"{s.get('bind_address')}:{s.get('port')}",
            f"{s.get('process')} ({s.get('pid') or 'kernel'})",
            "[bold red]LAN-Exposed[/bold red]" if s.get("lan_exposed") else "[dim]Loopback[/dim]",
        )
    console.print(tbl)


def cmd_cidr(cidr_str: str) -> None:
    res = calculate_subnet_cidr(cidr_str)
    if not res.get("ok"):
        console.print(f"[bold red]Invalid CIDR:[/bold red] {res.get('error')}")
        return
    console.print(
        Panel(
            f"[bold cyan]CIDR Block:[/bold cyan] [bold white]{res.get('cidr')}[/bold white] "
            f"(IPv{res.get('ip_version')} • {res.get('ip_class')} • {res.get('scope')})\n"
            f"[bold green]Network Address:[/bold green] {res.get('network_address')}  •  "
            f"[bold yellow]Broadcast:[/bold yellow] {res.get('broadcast_address')}\n"
            f"[bold cyan]Netmask:[/bold cyan] {res.get('netmask')}  •  "
            f"[bold magenta]Wildcard Mask:[/bold magenta] {res.get('hostmask')}\n"
            f"[bold white]Usable Host Range:[/bold white] {res.get('first_usable')}  ->  {res.get('last_usable')}\n"
            f"[bold emerald]Usable Hosts:[/bold emerald] {res.get('usable_hosts'):,} (Total Addresses: {res.get('total_addresses'):,})",
            title="IPv4 / IPv6 Subnet & CIDR Calculator",
            border_style="green",
        )
    )


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="netpulse",
        description="NetPulse (OmniSight) — Sovereign Network Intelligence & Deep Fingerprinting Suite",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("scan", help="Run an instant deep multi-vector subnet scan")
    sub.add_parser("watch", help="Run live auto-refreshing Terminal TUI Network Guardian")
    sub.add_parser("wifi", help="Scan 2.4/5 GHz Wi-Fi spectrum, hidden SSIDs, and Bluetooth 5.2 radar")
    sub.add_parser("speedtest", help="Run multi-stream WAN throughput, upload & bufferbloat benchmark")
    sub.add_parser("audit", help="Run Subnet Security Posture & Cryptographic Protocol Audit (SSH HASSH, SMB2, TLS)")

    p_oui = sub.add_parser("oui", help="Search 47,000+ IEEE OUI prefixes, vendors, or unmask SLAAC IPv6 EUI-64")
    p_oui.add_argument("query", help="MAC address, OUI prefix, vendor name, or IPv6 EUI-64 address")

    p_dom = sub.add_parser("domain", help="Deep DNS, SPF/DMARC, TLS X.509 & HTTP3 reconnaissance on a domain or IP")
    p_dom.add_argument("target", help="Target domain, URL, or IP address (e.g., cloudflare.com)")

    sub.add_parser("sockets", help="Audit local workstation listening ports, owning PIDs, and established connections")

    p_cidr = sub.add_parser("cidr", help="Calculate IPv4/IPv6 CIDR subnet boundaries, wildcard masks, and usable hosts")
    p_cidr.add_argument("cidr", nargs="?", default="192.168.12.0/24", help="CIDR block or IP/mask (default 192.168.12.0/24)")

    p_wol = sub.add_parser("wol", help="Send IEEE 802 Wake-on-LAN Magic Packet")
    p_wol.add_argument("mac", help="Target hardware MAC address")

    p_roku = sub.add_parser("roku", help="Send live Roku ECP remote keypress")
    p_roku.add_argument("ip", help="Roku TV or Stick IPv4 address")
    p_roku.add_argument("key", help="Key name (Home, PowerOff, PowerOn, VolumeUp, VolumeDown, VolumeMute, FindRemote, etc.)")

    p_serve = sub.add_parser("serve", help="Launch the Sovereign Real-Time Web Command Center")
    p_serve.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8765, help="Bind port (default 8765)")

    sub.add_parser("desktop", help="Launch the Native PyQt6 Desktop App + System Tray Guardian")
    sub.add_parser("export", help="Export Forensic Network & RF Intelligence Report to ~/Desktop")

    p_lic = sub.add_parser("license", help="Sovereign Cryptographic License & Subscription Manager")
    p_lic.add_argument(
        "action",
        choices=["status", "mint", "activate", "deactivate", "list", "revoke"],
        default="status",
        nargs="?",
        help="License action",
    )
    p_lic.add_argument("--tier", default="enterprise", choices=["pro", "enterprise"], help="Subscription tier to mint")
    p_lic.add_argument("--plan", default="lifetime", choices=["monthly", "annual", "lifetime", "trial"], help="Billing cycle")
    p_lic.add_argument("--email", default="founder@netpulse.local", help="Subscriber email or organization")
    p_lic.add_argument("--key", default="", help="License key to activate or JTI to revoke")
    p_lic.add_argument("--no-activate", action="store_true", help="Mint key without auto-activating on local node")

    args = parser.parse_args(argv)
    cmd = args.command or "desktop"

    if cmd == "scan":
        cmd_scan()
    elif cmd == "watch":
        cmd_watch()
    elif cmd == "wifi":
        cmd_wifi()
    elif cmd == "speedtest":
        cmd_speedtest()
    elif cmd == "audit":
        cmd_audit()
    elif cmd == "oui":
        cmd_oui(args.query)
    elif cmd == "domain":
        cmd_domain(args.target)
    elif cmd == "sockets":
        cmd_sockets()
    elif cmd == "cidr":
        cmd_cidr(args.cidr)
    elif cmd == "wol":
        ok, msg = send_wake_on_lan(args.mac)
        console.print(f"[{'green' if ok else 'red'}]{msg}[/{'green' if ok else 'red'}]")
    elif cmd == "roku":
        ok, msg = send_roku_keypress(args.ip, args.key)
        console.print(f"[{'green' if ok else 'red'}]{msg}[/{'green' if ok else 'red'}]")
    elif cmd == "desktop":
        from netpulse.desktop import launch_desktop_app
        launch_desktop_app()
    elif cmd == "export":
        from netpulse.desktop import ensure_daemon_running, DAEMON_URL
        import urllib.request, json
        ensure_daemon_running()
        req = urllib.request.Request(f"{DAEMON_URL}/api/export/report", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            res = json.loads(resp.read().decode())
            console.print(f"[bold green]{res.get('summary')}[/bold green]")
    elif cmd == "serve":
        host = getattr(args, "host", "0.0.0.0")
        port = getattr(args, "port", 8765)
        console.print(
            Panel(
                f"[bold green]Launching NETPULSE // OMNISIGHT Web Command Center[/bold green]\n"
                f"Local URL:  [bold cyan]http://localhost:{port}[/bold cyan]\n"
                f"LAN URL:    [bold cyan]http://192.168.12.225:{port}[/bold cyan]",
                border_style="cyan",
            )
        )
        uvicorn.run("netpulse.server:app", host=host, port=port, log_level="info")
    elif cmd == "license":
        from netpulse.billing import subscription_engine
        act = getattr(args, "action", "status")
        if act == "mint":
            minted = subscription_engine.mint_license_key(
                tier=args.tier,
                plan=args.plan,
                email=args.email,
            )
            if not args.no_activate:
                subscription_engine.activate_license_key(minted["license_key"])
            console.print(
                Panel(
                    f"[bold green]Minted Cryptographic NetPulse License Key[/bold green]\n"
                    f"License ID: [bold cyan]{minted['jti']}[/bold cyan]\n"
                    f"Tier:       [bold yellow]{minted['tier_name']}[/bold yellow] ({minted['plan'].upper()})\n"
                    f"Subscriber: [white]{minted['email']}[/white]\n"
                    f"Expires:    [white]{minted['expires_human']}[/white]\n"
                    f"Signed Key: [bold emerald]{minted['license_key']}[/bold emerald]",
                    title="Sovereign Key Generator",
                    border_style="green",
                )
            )
        elif act == "activate":
            res = subscription_engine.activate_license_key(args.key)
            console.print(res)
        elif act == "deactivate":
            res = subscription_engine.deactivate_license()
            console.print(res)
        elif act == "revoke":
            res = subscription_engine.revoke_license(args.key)
            console.print(res)
        elif act == "list":
            keys = subscription_engine.list_minted_licenses()
            t = Table(title="Minted NetPulse Cryptographic Licenses", box=box.ROUNDED)
            t.add_column("JTI", style="cyan")
            t.add_column("Tier", style="yellow")
            t.add_column("Plan")
            t.add_column("Subscriber")
            t.add_column("Expires")
            t.add_column("Status")
            t.add_column("License Key", style="dim")
            for k in keys:
                t.add_row(
                    k["jti"],
                    k["tier"].upper(),
                    k["plan"],
                    k["email"],
                    k["expires_human"],
                    "[red]REVOKED[/red]" if k["revoked"] else "[green]ACTIVE[/green]",
                    k["license_key"],
                )
            console.print(t)
        else:
            st = subscription_engine.get_subscription_status()
            console.print(
                Panel(
                    f"Active Tier: [bold cyan]{st['tier_name']}[/bold cyan] ({st['badge']})\n"
                    f"Subscriber:  [white]{st['email']}[/white]\n"
                    f"Expires:     [white]{st['expires_human']}[/white]\n"
                    f"License Key: [dim]{st['license_key_masked']}[/dim]",
                    title="NetPulse Node Subscription Status",
                    border_style="cyan",
                )
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
