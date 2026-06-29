"""
FamiSafe (Wondershare) application artifacts.

FamiSafe is a commercial "parental control" / monitoring application
(bundle identifiers ``com.wondershare.parentalcontrol``,
``com.wondershare.parentalcontrolkid`` and ``com.tencentmobile.famisafe``).
This module parses data that is *specific to FamiSafe* - i.e. stored inside the
application's own container with an application-specific structure - and that is
therefore out of scope for the generic, app-agnostic ``Surveillance.py`` module.

Two stores are parsed:

    1. The application URL cache (``Library/Caches/<bundle>/Cache.db``,
       table ``cfurl_cache_receiver_data``), which retains the controlling
       (parent) account e-mail address.
    2. The application run logs (``.../RunLogs/com.wondershare.parentalcontrol*``),
       split across three artifacts: the controlling (parent) account and the
       monitored device profile; the server-recorded install/activity window
       (device record created, first data collection, first/last backup,
       subscription expiry); and the monitoring features with whether each one is
       active (call/message monitoring, ambient sound, screen viewing,
       geofencing, ...). JSON carried in hex-encoded request/response bodies is
       decoded as well. The volatile on-device log timestamps are not used as an
       install indicator (logs rotate, so the earliest surviving entry is not the
       install time).

Only observed data is reported; no interpretation is added.

Developed as part of a master's thesis at the University of Lausanne (School of
Criminal Justice, digital forensic science), with the assistance of Claude Opus.
"""

import re
from pathlib import Path

from scripts.ilapfuncs import (
    artifact_processor,
    convert_unix_ts_to_utc,
    does_table_exist_in_db,
    get_sqlite_db_records,
    logfunc,
)


__artifacts_v2__ = {
    "famisafe_cached_accounts": {
        "name": "Controlling Account (URL cache)",
        "description": (
            "E-mail addresses recovered from the FamiSafe application URL cache "
            "(Cache.db, cfurl_cache_receiver_data). These typically correspond "
            "to the controlling (parent) account linked to the monitored device."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-14",
        "last_update_date": "2026-06-14",
        "requirements": "none",
        "category": "Famisafe",
        "notes": "Cache.db follows the standard CFURL cache schema; the content is FamiSafe-specific.",
        "paths": (
            "*/Caches/com.wondershare.parentalcontrol/Cache.db",      # FFS, backup
            "*/Caches/com.wondershare.parentalcontrolkid/Cache.db",   # FFS, backup
            "*/Caches/com.tencentmobile.famisafe/Cache.db",           # FFS, backup
        ),
        "output_types": "standard",
        "artifact_icon": "at-sign",
    },
    "famisafe_account": {
        "name": "Run Logs - Account and Device",
        "description": (
            "From the FamiSafe run logs: the controlling (parent) account "
            "details (e-mail, member id, uid, member code, country, account "
            "creation date) and the monitored device profile (nickname, age, "
            "device name / hardware model, OS, language, timezone, supervised)."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-14",
        "last_update_date": "2026-06-28",
        "requirements": "none",
        "category": "Famisafe",
        "notes": "Run-log format is specific to FamiSafe (Wondershare).",
        "paths": (
            "*/RunLogs/com.wondershare.parentalcontrol*",   # FFS, backup
            "*/RunLogs/com.tencentmobile.famisafe*",         # FFS, backup
        ),
        "output_types": "standard",
        "artifact_icon": "user",
    },
    "famisafe_install_window": {
        "name": "Run Logs - Install and Activity Window",
        "description": (
            "From the FamiSafe run logs: server-recorded install/activity dates "
            "(device record created, first data collection, first/last backup, "
            "last bind, MDM certificate installed, subscription expiry). These "
            "are authoritative timestamps from the FamiSafe API responses, not "
            "the volatile on-device log timestamps."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-14",
        "last_update_date": "2026-06-28",
        "requirements": "none",
        "category": "Famisafe",
        "notes": "Run-log format is specific to FamiSafe (Wondershare).",
        "paths": (
            "*/RunLogs/com.wondershare.parentalcontrol*",   # FFS, backup
            "*/RunLogs/com.tencentmobile.famisafe*",         # FFS, backup
        ),
        "output_types": "standard",
        "artifact_icon": "clock",
    },
    "famisafe_monitoring_features": {
        "name": "Run Logs - Monitoring Features",
        "description": (
            "From the FamiSafe run logs: the monitoring features (FamiSafe "
            "capabilities) remotely configured for the device - call/message "
            "monitoring, ambient-sound (microphone) recording, screen viewing, "
            "geofencing, app blocking, SOS, etc. - each with whether it is active."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-14",
        "last_update_date": "2026-06-28",
        "requirements": "none",
        "category": "Famisafe",
        "notes": "Run-log format is specific to FamiSafe (Wondershare).",
        "paths": (
            "*/RunLogs/com.wondershare.parentalcontrol*",   # FFS, backup
            "*/RunLogs/com.tencentmobile.famisafe*",         # FFS, backup
        ),
        "output_types": "standard",
        "artifact_icon": "eye",
    },
}


FAMISAFE_APPS = {
    "com.wondershare.parentalcontrol": "FamiSafe",
    "com.wondershare.parentalcontrolkid": "FamiSafe (Kid)",
    "com.tencentmobile.famisafe": "FamiSafe",
}

EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# JSON key:value (quoted string or number); also matches compact JSON.
KV_RE = re.compile(r'"([A-Za-z0-9_]+)"\s*:\s*(?:"([^"]*)"|(-?\d+))')
# Long hex blobs (request/response bodies) carry extra JSON once decoded.
HEX_RE = re.compile(r'\b([0-9a-fA-F]{40,})\b')
# App start line: 版本(version) | 系统版本(OS) | LAN(language) | model.
STARTUP_RE = re.compile(r"版本:([\w.]+)\s*\|\s*系统版本:([\w.]+)\s*\|\s*LAN:([\w-]+)\s*\|\s*model:(\S+)")

# Only keep e-mails hosted by a real, common mail provider. Internal FamiSafe
# addresses (e.g. *@famisafe.wondershare.com) and made-up domains are dropped.
REAL_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com",
    "icloud.com", "me.com", "mac.com",
    "outlook.com", "outlook.fr", "outlook.ch", "hotmail.com", "hotmail.fr",
    "live.com", "live.fr", "msn.com",
    "yahoo.com", "yahoo.fr", "ymail.com",
    "proton.me", "protonmail.com", "pm.me",
    "gmx.com", "gmx.net", "gmx.fr", "gmx.ch",
    "aol.com", "zoho.com", "fastmail.com", "hey.com",
    "bluewin.ch", "sunrise.ch", "hispeed.ch",
}

# JSON keys of interest in the FamiSafe API responses recorded in the logs.
# raw key (lowercase) -> (Category, normalised Field, kind: text|email|unixdate)
# Several raw keys map to the same Field so the same fact is reported once.
RUNLOG_FIELDS = {
    # Controlling (parent) account
    "parent_email": ("Parent account", "Parent account e-mail", "email"),
    "loginemail": ("Parent account", "Parent account e-mail", "email"),
    "email": ("Parent account", "Parent account e-mail", "email"),
    "member_id": ("Parent account", "FamiSafe member id", "text"),
    "spy_uid": ("Parent account", "FamiSafe member id", "text"),
    "memberid": ("Parent account", "FamiSafe member id", "text"),
    "uid": ("Parent account", "FamiSafe account uid", "text"),
    "member_code": ("Parent account", "FamiSafe member code", "text"),
    "member_level": ("Parent account", "Member level", "text"),
    "uninstall_code": ("Parent account", "Uninstall code", "text"),
    "country": ("Parent account", "Account country", "text"),
    "user_created_at": ("Parent account", "Parent account created", "unixdate"),
    # Monitored device / child profile
    "nickname": ("Monitored device", "Nickname", "text"),
    "age": ("Monitored device", "Age", "text"),
    "device_name": ("Monitored device", "Device name", "text"),
    "device_model": ("Monitored device", "Device model", "text"),
    "device_model_machine": ("Monitored device", "Hardware model", "text"),
    "device_brand": ("Monitored device", "Device brand", "text"),
    "device_version": ("Monitored device", "OS version", "text"),
    "device_language": ("Monitored device", "Device language", "text"),
    "timezone": ("Monitored device", "Timezone", "text"),
    "client_sign": ("Monitored device", "Client sign (install id)", "text"),
    "device_id": ("Monitored device", "FamiSafe device id", "text"),
    "bind_device_id": ("Monitored device", "FamiSafe device id", "text"),
    "is_supervised": ("Monitored device", "Supervised", "text"),
    "monitored": ("Monitored device", "Monitored", "text"),
    # Install / activity timing
    "created_at": ("Install / activity", "Device record created", "unixdate"),
    "first_gather_time": ("Install / activity", "First data collection", "unixdate"),
    "first_backup_time": ("Install / activity", "First backup", "unixdate"),
    "last_bind_time": ("Install / activity", "Last bind time", "unixdate"),
    "last_backup_time": ("Install / activity", "Last backup", "unixdate"),
    "install_certificate_time": ("Install / activity", "MDM certificate installed", "unixdate"),
    "expire": ("Install / activity", "Subscription expiry", "unixdate"),
}

# Monitoring features (FamiSafe "capabilities") and how their value is stored.
CAPABILITY_LABELS = {
    "monitor_calls_messages": "Calls/messages monitoring",
    "show_call_logs": "Call logs visible to parent",
    "ambient_sound": "Ambient sound (microphone) recording",
    "screen_viewer": "Screen viewing",
    "sos": "SOS",
    "drive_safety": "Driving safety",
    "suspicious_img": "Suspicious image detection",
    "safe_search": "Safe search",
    "gps_fence": "Geofencing",
    "app_block": "App blocking",
}
CAPABILITY_DIRECT = ("monitor_calls_messages", "show_call_logs")   # "key": <int>
CAPABILITY_ENABLE = ("ambient_sound", "screen_viewer", "sos",      # "key": { "enable": <int> }
                     "drive_safety", "suspicious_img", "safe_search")
CAPABILITY_ARRAY = ("gps_fence", "app_block")                      # "key": [ ... ]  (active if non-empty)


def _real_email(address):
    """Return the address if its domain is a known real provider, else ''. """
    domain = address.rsplit("@", 1)[-1].lower()
    return address if domain in REAL_EMAIL_DOMAINS else ""


def _unix_dt(value):
    """Convert a plausible unix-seconds value to UTC; None if implausible."""
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return None
    if 1_000_000_000 <= n <= 2_000_000_000:   # ~2001..2033
        return convert_unix_ts_to_utc(n)
    return None


def _iter_kv(text):
    """Yield (key_lower, value) JSON pairs from text, unescaping '\\/'. """
    for m in KV_RE.finditer(text):
        value = m.group(2) if m.group(2) is not None else m.group(3)
        yield m.group(1).lower(), value.replace("\\/", "/").strip()


def _decoded_hex_blobs(text):
    """Yield UTF-8 text decoded from long hex bodies embedded in the logs."""
    for token in HEX_RE.findall(text):
        if len(token) % 2:
            continue
        try:
            decoded = bytes.fromhex(token).decode("utf-8", "ignore")
        except ValueError:
            continue
        if '"' in decoded:
            yield decoded


def _capability_states(lines):
    """Map each monitoring feature to (raw_value, active?) from the config JSON.

    Values may be ints or strings, and "-1" means "not configured" (inactive);
    only an explicit 1 counts as active.
    """
    results = {}
    n = len(lines)
    for i, line in enumerate(lines):
        for key in CAPABILITY_DIRECT:
            m = re.search(rf'"{key}"\s*:\s*"?(-?\d+)"?', line)
            if m and key not in results:
                results[key] = (m.group(1), m.group(1) == "1")
        for key in CAPABILITY_ENABLE:
            if key not in results and re.search(rf'"{key}"\s*:\s*\{{', line):
                for j in range(i, min(i + 12, n)):
                    me = re.search(r'"enable"\s*:\s*"?(-?\d+)"?', lines[j])
                    if me:
                        results[key] = (f"enable={me.group(1)}", me.group(1) == "1")
                        break
        for key in CAPABILITY_ARRAY:
            if key not in results and re.search(rf'"{key}"\s*:\s*\[', line):
                rest = line.split("[", 1)[1].strip()
                if rest == "":
                    nxt = lines[i + 1].strip() if i + 1 < n else ""
                    active = not nxt.startswith("]")
                else:
                    active = not rest.startswith("]")
                results[key] = ("has entries" if active else "empty", active)
    return results


def _app_label_from_path(path):
    text = str(path)
    for bundle_id, label in FAMISAFE_APPS.items():
        if bundle_id in text:
            return label
    return "FamiSafe"


# ---------------------------------------------------------------------------
# Cache.db - controlling account
# ---------------------------------------------------------------------------

@artifact_processor
def famisafe_cached_accounts(context):
    data_headers = ("Account / E-mail", "Application", "Source Table", "Source File")
    data_list = []
    source_paths = []

    files_found = context.get_files_found()
    for file_found in files_found:
        if Path(file_found).name.lower() != "cache.db":
            continue
        source_paths.append(file_found)
        app_label = _app_label_from_path(file_found)

        if not does_table_exist_in_db(file_found, "cfurl_cache_receiver_data"):
            continue
        rows = get_sqlite_db_records(file_found, "SELECT receiver_data FROM cfurl_cache_receiver_data")
        emails = set()
        for (blob,) in rows:
            if not blob:
                continue
            # receiver_data may come back as bytes (BLOB) or str (TEXT storage);
            # normalise to bytes for the e-mail search.
            raw = blob if isinstance(blob, (bytes, bytearray)) else str(blob).encode("utf-8", "replace")
            for match in EMAIL_RE.findall(raw):
                emails.add(match.decode("latin-1"))

        for email in sorted(emails):
            data_list.append((email, app_label, "cfurl_cache_receiver_data", file_found))

    return data_headers, data_list, "; ".join(source_paths)


# ---------------------------------------------------------------------------
# RunLogs - account, device linkage and monitoring configuration
# ---------------------------------------------------------------------------

def _read_lines(path, max_lines=200000):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as ex:
        logfunc(f"FamiSafe: could not read {path}: {ex}")
        return []
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding, errors="replace").splitlines()[:max_lines]
        except Exception:
            continue
    return []


def _parse_runlogs(files_found):
    """Parse every run-log once into (facts, capabilities, source_paths).

    facts: {(category, field, value): (source, order)} - de-duplicated across the
    whole set so a fact is reported once even if it recurs.
    capabilities: {capability key: (raw_value, active, source)}.

    Note: the volatile on-device first/last log timestamps are intentionally NOT
    derived here. Logs rotate, so the earliest surviving log says nothing about
    when the app was installed; the authoritative install/activity dates come from
    the server-recorded fields in "Install / activity" instead.
    """
    facts = {}
    order = 0
    capabilities = {}
    source_paths = []

    def add_fact(category, field, value, source):
        nonlocal order
        value = (value or "").strip()
        if value:
            facts.setdefault((category, field, value), (source, order))
            order += 1

    def consume_kv(text, source):
        for key, value in _iter_kv(text):
            spec = RUNLOG_FIELDS.get(key)
            if not spec:
                continue
            category, field, kind = spec
            if kind == "email":
                value = _real_email(value)
            elif kind == "unixdate":
                dt = _unix_dt(value)
                value = str(dt) if dt else ""
            add_fact(category, field, value, source)

    for file_found in files_found:
        if Path(file_found).is_dir():
            continue
        source_paths.append(file_found)
        lines = _read_lines(file_found)
        text = "\n".join(lines)

        # App version / OS / language / model from the start line.
        for ver, os_ver, lang, model in STARTUP_RE.findall(text):
            add_fact("Monitored device", "FamiSafe app version", ver, file_found)
            add_fact("Monitored device", "OS version", os_ver, file_found)
            add_fact("Monitored device", "Device language", lang, file_found)
            add_fact("Monitored device", "Device model", model, file_found)

        # Account / device / timing fields from the JSON responses, including
        # JSON carried inside hex-encoded request/response bodies.
        consume_kv(text, file_found)
        for decoded in _decoded_hex_blobs(text):
            consume_kv(decoded, file_found)

        # Monitoring features (last config block seen wins).
        for key, (raw, active) in _capability_states(lines).items():
            capabilities[key] = (raw, active, file_found)

    return facts, capabilities, source_paths


def _facts_in(facts, categories):
    """Yield (category, field, value, source) for the given categories, in order."""
    for (category, field, value), (source, _o) in sorted(facts.items(), key=lambda kv: kv[1][1]):
        if category in categories:
            yield category, field, value, source


@artifact_processor
def famisafe_account(context):
    data_headers = ("Category", "Field", "Value", "Source File")
    facts, _caps, source_paths = _parse_runlogs(context.get_files_found())
    data_list = [(category, field, value, source) for category, field, value, source
                 in _facts_in(facts, {"Parent account", "Monitored device"})]
    return data_headers, data_list, "; ".join(source_paths)


@artifact_processor
def famisafe_install_window(context):
    data_headers = ("Field", "Value", "Source File")
    facts, _caps, source_paths = _parse_runlogs(context.get_files_found())
    data_list = [(field, value, source) for _category, field, value, source
                 in _facts_in(facts, {"Install / activity"})]
    return data_headers, data_list, "; ".join(source_paths)


@artifact_processor
def famisafe_monitoring_features(context):
    data_headers = ("Feature", "Configuration", "State", "Source File")
    _facts, capabilities, source_paths = _parse_runlogs(context.get_files_found())
    data_list = []
    for key in CAPABILITY_LABELS:
        if key in capabilities:
            raw, active, source = capabilities[key]
            data_list.append((CAPABILITY_LABELS[key], raw,
                              "active" if active else "inactive", source))
    return data_headers, data_list, "; ".join(source_paths)
