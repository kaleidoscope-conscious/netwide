"""Canonical probe-result keys to prevent prober↔fingerprint drift.

Historical drift examples (fixed):
  probers.py `ollama_ai`      -> fingerprint expected `ollama`
  probers.py Sonos camelCase  -> fingerprint snake_case
  probers.py Hue keys         -> fingerprint expected bridge_name/model_id
  probers.py MQTT anonymous   -> fingerprint expected auth_status
  probers mDNS `service`      -> consumers expected `service_type`

This module is the single source of truth for those shapes. Both
probers and fingerprint should import from here. Legacy aliases are
kept for backward compat.
"""
from __future__ import annotations

from typing import Any, Dict

# mDNS service entries: producer MUST emit both keys.
MDNS_SERVICE_KEYS = ("service", "service_type", "instance", "instance_name", "hostname", "port", "txt")

# Extended IoT probe canonical keys
EXT_IOT_KEYS = {
    "sonos": ("roomName", "room_name", "modelName", "model", "modelNumber", "model_number",
              "softwareVersion", "software_version", "serialNum", "serial_num", "MACAddress"),
    "philips_hue": ("bridgeid", "bridgeId", "bridge_name", "modelid", "model_id"),
    "ollama": ("models", "model_count"),
    "plex": ("version", "machine_id", "machine_identifier"),
    "docker_api": ("version", "api_version", "os"),
    "mqtt": ("anonymous_allowed", "auth_status", "connack_code", "status"),
}

# SMB security canonical keys
SMB_SECURITY_KEYS = (
    "dialect", "dialect_name", "dialect_rev", "signing_enabled",
    "signing_required", "security_mode", "ntlm_relay_vulnerable",
    "server_guid", "capabilities", "security_posture",
)

# Unified control capability taxonomy (see server: POST /api/control/...)
CONTROL_CAPABILITIES = {
    "power": ("on", "off", "toggle", "reboot", "standby"),
    "media": ("play", "pause", "stop", "next", "previous", "volume", "input", "launch_app", "keypress"),
    "lighting": ("brightness", "color", "temperature", "scene", "on", "off"),
    "network": ("reboot", "wol", "quarantine", "release", "bandwidth_limit"),
    "sensors": ("read",),
}

# Device kind taxonomy for the identity graph (GET /api/graph)
GRAPH_DEVICE_KINDS = (
    "network_device", "wireless_ap", "cellular_modem",
    "bt_device", "zigbee_node", "matter_node",
)
GRAPH_RELATIONS = (
    "same_radio", "talks_to", "masquerades_as", "controls", "observed_by",
)

def normalize_mdns_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure both legacy and canonical mDNS keys exist."""
    out = dict(entry)
    st = out.get("service_type") or out.get("service") or ""
    inst = out.get("instance_name") or out.get("instance") or ""
    out["service"] = st
    out["service_type"] = st
    out["instance"] = inst
    out["instance_name"] = inst
    return out

def normalize_extended_iot(ext: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror camelCase ↔ snake_case for Sonos/Hue/Plex so either reader works."""
    out = dict(ext)
    if "sonos" in out and isinstance(out["sonos"], dict):
        s = dict(out["sonos"])
        for camel, snake in [
            ("softwareVersion", "software_version"),
            ("serialNum", "serial_num"),
            ("roomName", "room_name"),
            ("modelName", "model"),
            ("modelNumber", "model_number"),
        ]:
            if camel in s and snake not in s:
                s[snake] = s[camel]
            if snake in s and camel not in s:
                s[camel] = s[snake]
        out["sonos"] = s
    if "plex" in out and isinstance(out["plex"], dict):
        p = dict(out["plex"])
        a = p.get("machine_identifier") or p.get("machine_id") or ""
        p["machine_id"] = a
        p["machine_identifier"] = a
        out["plex"] = p
    if "mqtt" in out and isinstance(out["mqtt"], dict):
        m = dict(out["mqtt"])
        anon = bool(m.get("anonymous_allowed"))
        m["auth_status"] = "anonymous_allowed" if anon else "authenticated"
        out["mqtt"] = m
    return out
