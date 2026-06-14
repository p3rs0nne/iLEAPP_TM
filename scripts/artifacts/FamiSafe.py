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
    2. The application run logs (``.../RunLogs/com.wondershare.parentalcontrol*.log``),
       which record the controlling account, the FamiSafe member/device
       identifiers, the application version, the API endpoints contacted and the
       monitoring capabilities that were enabled remotely (call/message
       monitoring, ambient sound, screen viewing, geofencing, ...).

Only observed data is reported; no interpretation is added.

Developed as part of a master's thesis at the University of Lausanne (School of
Criminal Justice, digital forensic science), with the assistance of Claude Opus.
"""

import re
from pathlib import Path

from scripts.ilapfuncs import (
    artifact_processor,
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
    # "famisafe_run_logs": {
    #     "name": "Run Logs (account, device, monitoring config)",
    #     "description": (
    #         "Identity, device linkage and monitoring configuration extracted "
    #         "from the FamiSafe run logs: controlling account e-mail, FamiSafe "
    #         "member/device identifiers, application version, API endpoints "
    #         "contacted and the monitoring capabilities enabled remotely."
    #     ),
    #     "author": "Julie / University of Lausanne (with Claude Opus)",
    #     "creation_date": "2026-06-14",
    #     "last_update_date": "2026-06-14",
    #     "requirements": "none",
    #     "category": "Famisafe",
    #     "notes": "Run-log format is specific to FamiSafe (Wondershare).",
    #     "paths": (
    #         "*/RunLogs/com.wondershare.parentalcontrol*",   # FFS, backup
    #         "*/RunLogs/com.tencentmobile.famisafe*",         # FFS, backup
    #     ),
    #     "output_types": "standard",
    #     "artifact_icon": "file-text",
    # },
}


FAMISAFE_APPS = {
    "com.wondershare.parentalcontrol": "FamiSafe",
    "com.wondershare.parentalcontrolkid": "FamiSafe (Kid)",
    "com.tencentmobile.famisafe": "FamiSafe",
}

EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")

# Capability flags worth surfacing from the remote configuration in the logs.
CAPABILITY_KEYS = (
    "monitor_calls_messages",
    "show_call_logs",
    "ambient_sound",
    "screen_viewer",
    "gps_fence",
    "sos",
    "app_block",
)


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


@artifact_processor
def famisafe_run_logs(context):
    data_headers = (
        ("First Seen", "datetime"),
        "Category",
        "Field",
        "Value",
        "Source File",
    )
    data_list = []
    source_paths = []

    member_id_re = re.compile(r"member_id=(\d+)")
    device_id_re = re.compile(r"device_id=(\d+)")
    client_ver_re = re.compile(r"X-Client-Ver:\s*([\w.]+)")
    user_agent_re = re.compile(r"User-Agent:\s*(FamiSafe[^\r\n]+)")
    host_re = re.compile(r"https?://([a-z0-9.\-]*famisafe\.com)", re.IGNORECASE)
    email_text_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    capability_re = re.compile(r'"?(' + "|".join(CAPABILITY_KEYS) + r')"?\s*[:=]')

    files_found = context.get_files_found()
    for file_found in files_found:
        if Path(file_found).is_dir():
            continue
        source_paths.append(file_found)
        app_label = _app_label_from_path(file_found)

        # Track distinct values so the output stays compact: value -> first ts.
        seen = {}  # (category, field, value) -> timestamp

        def record(category, field, value, ts):
            key = (category, field, value)
            if value and key not in seen:
                seen[key] = ts

        current_ts = ""
        for line in _read_lines(file_found):
            ts_match = TS_RE.match(line)
            if ts_match:
                current_ts = ts_match.group("ts")

            for match in email_text_re.findall(line):
                record("Account", "Account e-mail", match, current_ts)
            for mid in member_id_re.findall(line):
                record("Device linkage", "FamiSafe member_id", mid, current_ts)
            for did in device_id_re.findall(line):
                record("Device linkage", "FamiSafe device_id", did, current_ts)
            ver = client_ver_re.search(line)
            if ver:
                record("Application", "FamiSafe client version", ver.group(1), current_ts)
            ua = user_agent_re.search(line)
            if ua:
                record("Application", "User-Agent", ua.group(1).strip(), current_ts)
            for host in host_re.findall(line):
                record("Network", "API host", host.lower(), current_ts)
            if capability_re.search(line):
                record("Monitoring configuration", "Capability line", line.strip()[:300], current_ts)

        for (category, field, value), ts in seen.items():
            data_list.append((ts, category, field, value, file_found))

    return data_headers, data_list, "; ".join(source_paths)
