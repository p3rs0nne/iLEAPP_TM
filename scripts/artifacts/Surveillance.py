"""
Surveillance-oriented iLEAPP artifacts.

This module groups forensic traces by investigative question rather than by
storage format. It is organised around four questions an examiner asks when
looking for signs of interpersonal (intimate-partner / familial) surveillance
on an iOS device, plus a summary that aggregates the findings:

    1. Remote management profiles   (surveillance_remote_management)
    2. Sensitive permissions        (surveillance_sensitive_permissions)
    3. Account associations         (surveillance_account_associations)
    4. Pairing and backup traces    (surveillance_pairing_backup)

plus a summary (surveillance_summary) that rolls up the most important concrete
traces found across the four categories.

The four detail artifacts only state observed data; no interpretation is added
to their tables. The summary likewise states facts only: it lists the salient
traces (account identifiers, MDM enrolment, MDM-managed apps, third-party apps
with background/always location, paired computers, ...) and links each one back to the detail page
that holds the full context. It deliberately does NOT assign a severity or a
verdict. Each collector still computes severity "signals" internally, kept for a
possible future assessment view; the summary does not use them.

Designed to run against the three acquisition types used in the underlying
research: a local (iTunes/Finder/iMazing) backup, a full file system (FFS)
extraction, and a sysdiagnose archive.

Only data that generalises across applications (standard Apple stores) is
collected here. Data held inside a specific monitoring app's container, with an
app-specific structure, is handled by dedicated modules such as FamiSafe.py.

Apple Unified Logs: backup activity (BackupAgent2 "Starting/Finished backup"
events) is parsed from the sysdiagnose's system_logs.logarchive via the
forensic_aul library (see surveillance_unified_log_backups). Other unified-log
signals (mdmd / profiled profile events, lockdownd pairing timestamps) are
candidates for the same approach but are not parsed yet.

Developed as part of a master's thesis at the University of Lausanne (School of
Criminal Justice, digital forensic science), with the assistance of Claude Opus.
"""

import html
import json
import re
from pathlib import Path

from scripts.ilapfuncs import (
    artifact_processor,
    attach_sqlite_db_readonly,
    convert_cocoa_core_data_ts_to_utc,
    convert_plist_date_to_utc,
    convert_unix_ts_to_utc,
    does_column_exist_in_db,
    does_table_exist_in_db,
    get_plist_file_content,
    get_sqlite_db_records,
    logfunc,
)


__artifacts_v2__ = {
    "surveillance_remote_management": {
        "name": "Surveillance - Remote Management Profiles",
        "description": (
            "Configuration / MDM profiles installed on the device and the "
            "restrictions they enforce (forced encrypted backup, VPN), the list "
            "of managed applications and the history of settings changes. A "
            "remote-management profile on a personal device is one of the most "
            "significant surveillance indicators."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-05-30",
        "last_update_date": "2026-06-14",
        "requirements": "none",
        "category": "Surveillance",
        "notes": "Truth.plist, EffectiveUserSettings.plist, MDMAppManagement.plist, "
                 "MCSettingsEvents.plist, MCState/Shared/MDM.plist and profile stubs.",
        "paths": (
            "*/UserConfigurationProfiles/PublicInfo/Truth.plist",       # FFS, backup
            "*/UserConfigurationProfiles/EffectiveUserSettings.plist",  # FFS, backup
            "*/ConfigurationProfiles/MDMAppManagement.plist",           # FFS, backup
            "*/ConfigurationProfiles/MCSettingsEvents.plist",           # FFS, backup
            "*/ConfigurationProfiles/ProfileTruth.plist",               # FFS, backup
            "*/ConfigurationProfiles/*.stub",                           # FFS, backup
            "*/MCState/Shared/MDM.plist",                               # sysdiagnose
            "*/MCState/Shared/PayloadDependency.plist",                 # sysdiagnose
            "*/MCState/Shared/MCSettingsEvents.plist",                  # sysdiagnose
            "*/MCState/Shared/ProfileTruth.plist",                      # sysdiagnose
            "*/MCState/Shared/*.stub",                                  # sysdiagnose
            "*/MCState/User/*.stub",                                    # sysdiagnose
        ),
        "output_types": "standard",
        "artifact_icon": "shield",
    },
    "surveillance_sensitive_permissions": {
        "name": "Surveillance - Sensitive Permissions",
        "description": (
            "Privacy permissions most relevant to monitoring (microphone, photo "
            "library, motion, Bluetooth, camera, location) from TCC.db, completed "
            "by location authorisation read from locationd's clients.plist - a "
            "file iLEAPP does not otherwise parse - which can reveal an "
            "always/background location authorisation."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-05-30",
        "last_update_date": "2026-06-14",
        "requirements": "none",
        "category": "Surveillance",
        "notes": "clients.plist parsing is a specific contribution of this module.",
        "paths": (
            "*/mobile/Library/TCC/TCC.db*",       # FFS, backup
            "*/Accessibility/TCC.db*",             # sysdiagnose
            "*/Caches/locationd/clients.plist",    # FFS, backup
        ),
        "output_types": "standard",
        "artifact_icon": "key",
    },
    "surveillance_account_associations": {
        "name": "Surveillance - Account Associations",
        "description": (
            "Traces showing a third-party account associated with the device: "
            "family-circle membership, an account added to iMessage, and "
            "location sharing."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-05-30",
        "last_update_date": "2026-06-14",
        "requirements": "none",
        "category": "Surveillance",
        "notes": "Application-specific account stores are handled by dedicated "
                 "modules such as FamiSafe.py.",
        "paths": (
            "*/Caches/FamilyCircle/CircleCache.plist",                    # FFS, backup
            "*/CircleCache.plist",                                        # FFS, backup
            "*/DuetExpertCenter/caches/familyCircleCache",                # FFS, backup
            "*/JFamilyCircle.plist",                                      # FFS, backup
            "*/com.apple.remotemanagementd/RMAdminStore-Local.sqlite*",   # FFS, backup
            "*/com.apple.transparencyd/TransparencyModel.sqlite*",        # FFS, backup
            "*/IdentityServices/idstatuscache.plist",                     # FFS, backup
            "*Identity Lookup Service.tsv",                               # iLEAPP TSV export (from FFS/backup)
        ),
        "output_types": "standard",
        "artifact_icon": "users",
    },
    "surveillance_pairing_backup": {
        "name": "Surveillance - Pairing and Backup Traces",
        "description": (
            "Evidence that the device was paired with a computer and that local "
            "backups were performed: trusted-host identifiers (SystemBUID, "
            "HostID, host name) from the lockdown log and pair records, the "
            "backup library identifier, and current/previous backup dates."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-05-30",
        "last_update_date": "2026-06-14",
        "requirements": "none",
        "category": "Surveillance",
        "notes": "BackupAgent2 start/finish unified-log events are parsed "
                 "separately by surveillance_unified_log_backups.",
        "paths": (
            "*/MobileLockdown/lockdownd.log",                      # sysdiagnose
            "*/MobileLockdown/lockdownd.log.1",                    # sysdiagnose
            "*/logs/lockdownd.log",                               # sysdiagnose
            "*/logs/lockdown.log",                               # sysdiagnose
            "*/lockdown.log",                                     # FFS (/private/var/db/lockdown)
            "*/Lockdown/pair_records/*.plist",                    # FFS, backup
            "*/Library/Preferences/com.apple.atc.plist",          # FFS, backup
            "*/Library/Preferences/com.apple.ldbackup.plist",     # FFS, backup
            "*/Library/Preferences/com.apple.MobileBackup.plist", # FFS, backup
            "*/root/Library/Lockdown/data_ark.plist",             # FFS, backup
            "*/Lockdown/com.apple.ldpair.plist",                  # FFS, backup
            "info.plist",                                         # backup (iTunes/Finder backup root)
        ),
        "output_types": "standard",
        "artifact_icon": "save",
    },
    "surveillance_unified_log_backups": {
        "name": "Surveillance - Unified Log Backup Events",
        "description": (
            "Local (computer) backup activity recorded in the Apple Unified Logs, "
            "parsed from a sysdiagnose (system_logs.logarchive) or an FFS "
            "(var/db/diagnostics + var/db/uuidtext). "
            "Reports only backups where a connected computer ran BackupAgent2 "
            "through the com.apple.mobilebackup2 lockdown service - the "
            "surveillance-relevant case. iCloud backups (backupd, the device's own "
            "routine) are deliberately excluded. Unlike the static backup plists, "
            "the unified logs date each backup session with its exact duration. "
            "Unified-log entries have a limited retention (~14 days for backup "
            "events), so the absence of an event is not proof that no backup "
            "occurred."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-28",
        "last_update_date": "2026-06-28",
        "requirements": "Requires the forensic_aul package (scripts/faul_lib) to "
                        "parse the unified logs.",
        "category": "Surveillance",
        "notes": "Extracts the unified logs with forensic_aul (-> SQLite) then reads "
                 "BackupAgent2 events. The parse is done once per run and shared with "
                 "the other unified-log artifacts (DB in the run's _unified_logs "
                 "folder). Heavy: parsing the unified logs takes a few minutes.",
        "paths": (
            "*/system_logs.logarchive/*",   # sysdiagnose (whole logarchive bundle)
            "*/var/db/diagnostics/*",       # FFS (tracev3 material)
            "*/var/db/uuidtext/*",          # FFS (format-string tables)
        ),
        "output_types": ["html", "tsv", "timeline"],
        "artifact_icon": "save",
    },
    "surveillance_unified_log_companion": {
        "name": "Surveillance - Unified Log Paired Computer Presence",
        "description": (
            "Companion-link / Rapport discovery of paired computers in the Apple "
            "Unified Logs (from a sysdiagnose logarchive or an FFS "
            "var/db/diagnostics + var/db/uuidtext). Each time a "
            "trusted computer is near or connected (over USB / Bluetooth LE / "
            "Wi-Fi), iOS logs it by name with its hardware addresses. This dates "
            "WHEN a specific named computer was physically present - the temporal "
            "counterpart to the static pairing records - and typically brackets a "
            "local backup session. The on-device 'atc' transport daemon does NOT "
            "log the sync host to the unified logs (only its own lifecycle), so "
            "this companion-link discovery is used instead."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-28",
        "last_update_date": "2026-06-28",
        "requirements": "Requires the forensic_aul package (scripts/faul_lib) to "
                        "parse the unified logs.",
        "category": "Surveillance",
        "notes": "com.apple.rapport / com.apple.CoreUtils companion-link events. "
                 "Shares the once-per-run unified-log parse with the other "
                 "unified-log artifacts. Heavy: parsing takes a few minutes.",
        "paths": (
            "*/system_logs.logarchive/*",   # sysdiagnose (whole logarchive bundle)
            "*/var/db/diagnostics/*",       # FFS (tracev3 material)
            "*/var/db/uuidtext/*",          # FFS (format-string tables)
        ),
        "output_types": ["html", "tsv", "timeline"],
        "artifact_icon": "monitor",
    },
    "surveillance_summary": {
        "name": "Surveillance - Summary of Key Traces",
        "description": (
            "A roll-up of the most important concrete traces found across the "
            "four surveillance categories: account identifiers, MDM enrolment "
            "and the applications it manages, third-party apps with background/"
            "always location, and paired computers. This is an index, not an "
            "assessment: it assigns no severity or verdict, and the 'Verify in' "
            "column links each trace to the detail page that holds its full "
            "context."
        ),
        "author": "Julie / University of Lausanne (with Claude Opus)",
        "creation_date": "2026-06-14",
        "last_update_date": "2026-06-28",
        "requirements": "none",
        "category": "Surveillance",
        "notes": "Reads the same files as the four detail artifacts (union of "
                 "their paths) and surfaces only the salient identifiers. The "
                 "'Verify in' column contains an HTML link to the relevant "
                 "detail artifact page.",
        # The "Verify in" column holds raw HTML (a link) and must not be escaped.
        "html_columns": ["Verify in"],
        # Union of the four categories' paths (see each category above for the
        # source type - FFS / backup / sysdiagnose - of every file).
        "paths": (
            "*/UserConfigurationProfiles/PublicInfo/Truth.plist",       # FFS, backup
            "*/UserConfigurationProfiles/EffectiveUserSettings.plist",  # FFS, backup
            "*/ConfigurationProfiles/MDMAppManagement.plist",           # FFS, backup
            "*/ConfigurationProfiles/MCSettingsEvents.plist",           # FFS, backup
            "*/ConfigurationProfiles/ProfileTruth.plist",               # FFS, backup
            "*/ConfigurationProfiles/*.stub",                           # FFS, backup
            "*/MCState/Shared/MDM.plist",                               # sysdiagnose
            "*/MCState/Shared/PayloadDependency.plist",                 # sysdiagnose
            "*/MCState/Shared/MCSettingsEvents.plist",                  # sysdiagnose
            "*/MCState/Shared/ProfileTruth.plist",                      # sysdiagnose
            "*/MCState/Shared/*.stub",                                  # sysdiagnose
            "*/MCState/User/*.stub",                                    # sysdiagnose
            "*/mobile/Library/TCC/TCC.db*",                             # FFS, backup
            "*/Accessibility/TCC.db*",                                  # sysdiagnose
            "*/Caches/locationd/clients.plist",                         # FFS, backup
            "*/Caches/FamilyCircle/CircleCache.plist",                  # FFS, backup
            "*/CircleCache.plist",                                      # FFS, backup
            "*/DuetExpertCenter/caches/familyCircleCache",              # FFS, backup
            "*/JFamilyCircle.plist",                                    # FFS, backup
            "*/com.apple.remotemanagementd/RMAdminStore-Local.sqlite*", # FFS, backup
            "*/com.apple.transparencyd/TransparencyModel.sqlite*",      # FFS, backup
            "*/IdentityServices/idstatuscache.plist",                   # FFS, backup
            "*Identity Lookup Service.tsv",                            # iLEAPP TSV export
            "*/MobileLockdown/lockdownd.log",                          # sysdiagnose
            "*/MobileLockdown/lockdownd.log.1",                        # sysdiagnose
            "*/logs/lockdownd.log",                                    # sysdiagnose
            "*/logs/lockdown.log",                                     # sysdiagnose
            "*/lockdown.log",                                          # FFS
            "*/Lockdown/pair_records/*.plist",                         # FFS, backup
            "*/Library/Preferences/com.apple.atc.plist",               # FFS, backup
            "*/Library/Preferences/com.apple.ldbackup.plist",          # FFS, backup
            "*/Library/Preferences/com.apple.MobileBackup.plist",      # FFS, backup
            "*/root/Library/Lockdown/data_ark.plist",                  # FFS, backup
            "*/Lockdown/com.apple.ldpair.plist",                       # FFS, backup
            "info.plist",                                              # backup root
        ),
        "output_types": ["html", "tsv"],
        "artifact_icon": "alert-triangle",
    },
    # "notifications_surveillance": {
    #     "name": "Notifications and Export Emails (Surveillance)",
    #     "description": (
    #         "Finds Apple Mail records whose sender, subject, or summary "
    #         "matches configurable export or account-access patterns."
    #     ),
    #     "author": "Julie / Codex",
    #     "creation_date": "2026-05-30",
    #     "last_update_date": "2026-06-14",
    #     "requirements": "none",
    #     "category": "Surveillance",
    #     "notes": "Parsing logic retained for reference but currently disabled: "
    #              "this artifact intentionally returns no rows.",
    #     "paths": (
    #         "*/mobile/Library/Mail/Envelope Index*",
    #         "*/mobile/Library/Mail/Protected Index*",
    #     ),
    #     "output_types": "standard",
    #     "artifact_icon": "mail",
    # },
}


# ---------------------------------------------------------------------------
# Reference data (not paths - kept as constants, easy to extend)
# ---------------------------------------------------------------------------

# No hard-coded list of "known" monitoring apps / vendors is kept: such allow-lists
# go stale immediately (new stalkerware ships constantly) and are a maintenance
# burden. Detection is behaviour-based instead - the summary flags any third-party
# (non-Apple) app with background/always location and any MDM-managed app, which is
# robust to unknown apps. The detail tables always report every app/permission raw.

# TCC services of particular interest in a surveillance context.
SENSITIVE_TCC_SERVICES = {
    "kTCCServiceMicrophone": "microphone access",
    "kTCCServicePhotos": "photo library access",
    "kTCCServicePhotosAdd": "photo library write access",
    "kTCCServiceMotion": "motion and fitness access",
    "kTCCServiceCamera": "camera access",
    "kTCCServiceLocation": "location access",
}

# Values of the "Authorization" key in locationd's clients.plist.
# Source (tested, not the CLAuthorizationStatus enum): The Forensic Scooter,
# "iOS Location Services and System Services ON or OFF?" (2021-09-20),
# https://theforensicscooter.com/2021/09/20/ios-location-services-and-system-services-on-or-off/
# A missing Authorization key corresponds to "Ask Next Time".
LOCATION_AUTH_STATUS = {
    1: "Never (app) / Off (system service)",
    2: "While Using the App",
    4: "Always Allow (app) / On (system service)",
    5: "Allow Once (temporary)",
}

# Case-specific email wording for the (currently disabled) notifications module.
EMAIL_EXPORT_REGEXES = [
    r"\bdata\s+(export|download|archive|request)\b",
    r"\b(export|download|archive).{0,50}\b(data|information|privacy)\b",
    r"\bprivacy.{0,50}\b(export|download|request|archive)\b",
    r"\byour\s+apple\s+data\b",
    r"\bapple\s+data\s+and\s+privacy\b",
    r"\bdownload\s+your\s+data\b",
    r"\btakeout\b",
]

# Severity scale used to derive the summary assessment.
SEV_HIGH = 3
SEV_MEDIUM = 2
SEV_INFO = 1


# ---------------------------------------------------------------------------
# Small generic helpers
# ---------------------------------------------------------------------------

def _dedupe(seq):
    seen, out = set(), []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _decode_bytes(value):
    if value is None:
        return ""
    if not isinstance(value, bytes):
        return value
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            decoded = value.decode(encoding).strip("\x00")
            if decoded:
                return decoded
        except UnicodeDecodeError:
            continue
    return value.hex()


def _safe_json_default(value):
    if isinstance(value, bytes):
        return _decode_bytes(value)
    return str(value)


def _format_value(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return _decode_bytes(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=_safe_json_default)
    return str(value)


def _short_text(value, limit=900):
    text = _format_value(value).replace("\r", " ").replace("\n", " ")
    return text[: limit - 3] + "..." if len(text) > limit else text


def _dedupe_rows(rows, source_index=-1):
    """Drop rows that repeat the same information in another source file."""
    out, seen = [], set()
    for row in rows:
        key = tuple(_format_value(v) for i, v in enumerate(row) if i != source_index)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _coredata_ts(value):
    if value in (None, ""):
        return ""
    try:
        if isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()):
            value = float(value) if "." in value else int(value)
        return convert_cocoa_core_data_ts_to_utc(value)
    except Exception:
        return _format_value(value)


def _unix_ts(value):
    if value in (None, ""):
        return ""
    try:
        return convert_unix_ts_to_utc(value)
    except Exception:
        return _format_value(value)


def _plist_ts(value):
    if value in (None, ""):
        return ""
    try:
        return convert_plist_date_to_utc(value)
    except Exception:
        return _format_value(value)


def _read_text_lines(path, max_lines=40000):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as ex:
        logfunc(f"Surveillance: could not read {path}: {ex}")
        return []
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding, errors="replace").splitlines()[:max_lines]
        except Exception:
            continue
    return []


def _iter_plist_values(value, interesting_keys, path="root"):
    """Yield (key_path, key, value) for keys matching interesting_keys."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            key_text = str(key)
            if key_text in interesting_keys or any(t.lower() in key_text.lower() for t in interesting_keys):
                yield child, key_text, item
            yield from _iter_plist_values(item, interesting_keys, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_plist_values(item, interesting_keys, f"{path}[{index}]")


def _quote_identifier(identifier):
    return '"' + str(identifier).replace('"', '""') + '"'


def _fetch_existing_columns(db_path, table_name, wanted_columns, limit=1000):
    """Fetch only the requested columns that actually exist in a table.

    Schema checks and the query both go through ilapfuncs helpers
    (does_column_exist_in_db / get_sqlite_db_records).
    """
    selected = [c for c in wanted_columns if does_column_exist_in_db(db_path, table_name, c)]
    if not selected:
        return [], []
    query = ("SELECT " + ", ".join(_quote_identifier(c) for c in selected)
             + f" FROM {_quote_identifier(table_name)} LIMIT {int(limit)}")
    return selected, get_sqlite_db_records(db_path, query)


# ===========================================================================
# Category 1 - Remote management profiles
# ===========================================================================

# "Profile / Context" groups rows by the profile (or source/actor) they belong
# to; "Configures" says what the row controls - for a profile payload this is the
# decoded PayloadType, so it is clear which app/service each payload governs.
REMOTE_MANAGEMENT_HEADERS = ("Indicator", "Profile / Context", "Configures", "Detail", "Source File")

_RM_PLISTS = {
    "mdm.plist", "mdmappmanagement.plist", "truth.plist", "profiletruth.plist",
    "effectiveusersettings.plist", "publiceffectiveusersettings.plist",
    "mcsettingsevents.plist", "payloaddependency.plist",
}

# Plain-language meaning of common configuration-profile payload types, so a
# reader can tell what each payload actually controls.
PAYLOAD_TYPE_LABELS = {
    "Configuration": "Profile container",
    "com.apple.applicationaccess": "Restrictions",
    "com.apple.applicationaccess.new": "Restrictions",
    "com.apple.applicationaccess.rules": "App access rules",
    "com.apple.webcontent-filter": "Web content filter",
    "com.apple.mobiledevice.passwordpolicy": "Passcode policy",
    "com.apple.wifi.managed": "Wi-Fi",
    "com.apple.vpn.managed": "VPN",
    "com.apple.vpn.managed.applayer": "Per-app VPN",
    "com.apple.dnsSettings.managed": "DNS settings",
    "com.apple.dnsProxy.managed": "DNS proxy",
    "com.apple.proxy.http.global": "Global HTTP proxy",
    "com.apple.webClip.managed": "Web clip",
    "com.apple.mdm": "MDM enrolment",
    "com.apple.email.account": "Email account",
    "com.apple.MCX": "Managed preferences",
    "com.apple.cellular": "Cellular",
    "com.apple.security.pkcs12": "Certificate (PKCS#12)",
    "com.apple.security.pkcs1": "Certificate",
    "com.apple.security.pem": "Certificate (PEM)",
    "com.apple.security.root": "Certificate (root CA)",
    "com.apple.security.scep": "SCEP certificate enrolment",
}


def _payload_label(payload_type):
    return PAYLOAD_TYPE_LABELS.get(payload_type, payload_type or "payload")


def _parse_profile_stub(stub, file_found):
    """Yield grouped rows describing a configuration-profile stub.

    One row identifies the profile itself; then one row per contained payload
    states what that payload configures (decoded PayloadType) together with its
    identifier, organisation and description/settings - so it is clear which
    app/service each payload controls. PayloadVersion and PayloadUUID are
    intentionally omitted (not informative for this purpose).
    """
    profile = stub.get("PayloadDisplayName") or stub.get("PayloadIdentifier") or Path(file_found).name
    prof_detail = "; ".join(part for part in (
        f"id={stub.get('PayloadIdentifier', '')}" if stub.get("PayloadIdentifier") else "",
        f"org={stub.get('PayloadOrganization', '')}" if stub.get("PayloadOrganization") else "",
        _short_text(stub.get("PayloadDescription", "")),
    ) if part)
    yield ("Configuration profile", profile, _payload_label(stub.get("PayloadType")),
           prof_detail, file_found)

    payloads = stub.get("PayloadContent")
    if not isinstance(payloads, list):
        return
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        label = _payload_label(payload.get("PayloadType"))
        display = payload.get("PayloadDisplayName") or ""
        configures = label if (not display or display.lower() == label.lower()) else f"{label} ({display})"
        settings = sorted(k for k in payload if not k.startswith("Payload"))
        detail = "; ".join(part for part in (
            f"id={payload.get('PayloadIdentifier', '')}" if payload.get("PayloadIdentifier") else "",
            f"org={payload.get('PayloadOrganization', '')}" if payload.get("PayloadOrganization") else "",
            _short_text(payload.get("PayloadDescription", "")),
            ("settings: " + ", ".join(settings)) if settings else "",
        ) if part)
        yield ("Profile payload", profile, configures, detail, file_found)


def _collect_remote_management(files_found):
    """Return (rows, signals, sources, key_traces) for the remote-management category."""
    rows, signals, sources, key_traces = [], [], [], []
    has_mdm = ""
    mdm_server = mdm_checkin = ""
    profile_count = 0
    force_encrypted_backup = vpn_indicator = False

    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()

        # Skip macOS AppleDouble sidecar files (e.g. "._profile-….stub") that an
        # archive may carry alongside the real file; they are not plists.
        if name.startswith("._"):
            continue

        if name.endswith(".stub"):
            profile_count += 1
            sources.append(file_found)
            # A stub is usually a (binary) plist; if it parses, surface the
            # profile and its payloads grouped together. If it is not a plist,
            # keep only a presence row.
            stub = get_plist_file_content(file_found)
            if isinstance(stub, dict):
                rows.extend(_parse_profile_stub(stub, file_found))
            else:
                rows.append(("Configuration profile present", Path(file_found).name,
                             "profile stub", "", file_found))
            continue

        if name not in _RM_PLISTS:
            continue
        data = get_plist_file_content(file_found)
        if not isinstance(data, dict):
            continue
        sources.append(file_found)

        if name == "mdm.plist":
            has_mdm = "mdm"
            for field in ("ServerURL", "CheckInURL", "Topic", "AccessRights",
                          "ManagingProfileIdentifier", "IdentityCertificateUUID",
                          "LastPollingSuccess", "LastPollingAttempt"):
                if field in data:
                    rows.append(("MDM enrollment", "(MDM)", field, _short_text(data[field]), file_found))
                    if field == "ServerURL":
                        mdm_server = _short_text(data[field])
                    elif field == "CheckInURL":
                        mdm_checkin = _short_text(data[field])

        elif name == "mdmappmanagement.plist":
            managed = data.get("metadataByBundleID", {})
            if isinstance(managed, dict):
                # Any app an MDM manages on a personal device is surveillance-
                # relevant, whatever it is - flag them all (behaviour, not identity).
                for bundle_id, _meta in managed.items():
                    rows.append(("Managed application", "(MDM-managed)", "app bundle id",
                                 bundle_id, file_found))
                    signals.append((SEV_HIGH, "MDM-managed application", bundle_id))
                    key_traces.append(("MDM-managed application", bundle_id))

        elif name in ("truth.plist", "profiletruth.plist"):
            for _kp, key, value in _iter_plist_values(data, {"forceEncryptedBackup"}):
                pref = value.get("preference") if isinstance(value, dict) else value
                rows.append(("Restriction", "Truth.plist", key, _format_value(pref), file_found))
                if pref is True or str(pref).lower() in ("1", "true", "yes"):
                    force_encrypted_backup = True

        elif name in ("effectiveusersettings.plist", "publiceffectiveusersettings.plist"):
            for _kp, key, value in _iter_plist_values(data, {"vpn"}):
                inner = value.get("value", value.get("preference", value)) if isinstance(value, dict) else value
                rows.append(("Restriction", "EffectiveUserSettings", key, _format_value(inner), file_found))
                vpn_indicator = True

        elif name == "mcsettingsevents.plist":
            # Only keep settings changed by an app or an MDM/profile mechanism;
            # changes made by ordinary system processes are not of interest.
            for setting, kind, event, process, ts in _iter_settings_events(data):
                if _is_app_or_mdm_process(process):
                    rows.append(("Settings change", process, setting,
                                 f"{event} {kind} @ {ts}", file_found))

        elif name == "payloaddependency.plist":
            for kp, key, value in _iter_plist_values(data, {"PayloadIdentifier", "Payload"}):
                rows.append(("Profile payload dependency", "(profile)", key, _short_text(value), file_found))

    if has_mdm:
        signals.append((SEV_HIGH, "Remote management (MDM) enrolled on device", "MDM profile present"))
        detail = "; ".join(p for p in (
            f"server={mdm_server}" if mdm_server else "",
            f"check-in={mdm_checkin}" if mdm_checkin else "",
        ) if p) or "MDM profile present"
        key_traces.append(("MDM (remote management) enrolled", detail))
    if profile_count:
        signals.append((SEV_MEDIUM, "Configuration profile(s) installed", f"{profile_count} profile stub(s)"))
        key_traces.append(("Configuration profiles installed", f"{profile_count} profile stub(s)"))
    if force_encrypted_backup:
        signals.append((SEV_MEDIUM, "Encrypted backup forced by profile", "Truth.plist forceEncryptedBackup"))
        key_traces.append(("Encrypted backup forced by profile", "Truth.plist forceEncryptedBackup"))
    if vpn_indicator:
        signals.append((SEV_MEDIUM, "VPN governed by configuration profile", "EffectiveUserSettings.plist"))
    return rows, signals, _dedupe(sources), key_traces


def _is_app_or_mdm_process(process):
    """True if a settings change was made by an app or an MDM/profile mechanism.

    Keeps profile/MDM daemons (profiled, mdmd, MCProfileServiceServer, ...) and
    third-party bundle IDs; drops ordinary Apple/system processes.
    """
    p = (process or "").lower()
    if any(token in p for token in ("profil", "mdm", "managedconfig", "mcprofile", "remotemanage")):
        return True
    # Reverse-DNS bundle ID that is not an Apple first-party process.
    return "." in p and not p.startswith("com.apple.")


def _iter_settings_events(data, path=()):
    """Yield (setting, kind, event, process, timestamp) from MCSettingsEvents.plist.

    Structure: <category>.<settingName>.<"value"|"ask">.{process, event, timestamp}.
    The setting name is the path component above the "value"/"ask" key.
    """
    if isinstance(data, dict):
        if "process" in data and "timestamp" in data:
            setting = path[-2] if len(path) >= 2 else (path[-1] if path else "")
            kind = path[-1] if path else ""
            yield (setting, kind, data.get("event", ""), data.get("process", ""),
                   _format_value(data.get("timestamp", "")))
            return
        for key, value in data.items():
            yield from _iter_settings_events(value, path + (str(key),))


@artifact_processor
def surveillance_remote_management(context):
    files_found = context.get_files_found()
    rows, _signals, sources, _traces = _collect_remote_management(files_found)
    return REMOTE_MANAGEMENT_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Category 2 - Sensitive permissions
# ===========================================================================

# One row per app: the list of sensitive permissions / location capabilities that
# app holds. TCC.db (microphone, camera, photos, motion, ...) and locationd's
# clients.plist (location authorisation and background-location capability) are
# merged, so a reader sees, per app, everything sensitive it can reach - with the
# location-capable apps surfaced first. TCC access decoding mirrors iLEAPP's own
# tcc.py (0=Not allowed, 2=Allowed, 3=Limited).
SENSITIVE_PERMISSIONS_HEADERS = (
    "App / Client", "Bundle ID", "Sensitive Permissions", "Source File",
)


def _tcc_access_label(raw_value, has_auth_value):
    """Decode the TCC access value exactly as iLEAPP's tcc.py does."""
    if raw_value is None:
        return ""
    if has_auth_value:
        return {0: "Not allowed", 2: "Allowed", 3: "Limited"}.get(raw_value, str(raw_value))
    return {0: "Not allowed", 1: "Allowed"}.get(raw_value, str(raw_value))


def _app_entry(apps, bundle_id, fallback_key):
    """Return the per-app aggregation record, creating it on first use."""
    key = bundle_id or fallback_key
    if key not in apps:
        shown_bundle = bundle_id if ("." in (bundle_id or "") and "/" not in bundle_id) else ""
        apps[key] = {
            "name": bundle_id or fallback_key,
            "bundle": shown_bundle,
            "perms": [],
            "sources": set(),
            "has_location": False,
        }
    return apps[key]


def _read_tcc(file_found, apps):
    if not does_table_exist_in_db(file_found, "access"):
        return
    has_auth_value = does_column_exist_in_db(file_found, "access", "auth_value")
    has_last_modified = does_column_exist_in_db(file_found, "access", "last_modified")
    access_column = "auth_value" if has_auth_value else "allowed"
    selected = (["last_modified"] if has_last_modified else []) + ["client", "service", access_column]

    services = "', '".join(SENSITIVE_TCC_SERVICES)
    query = ("SELECT " + ", ".join(_quote_identifier(c) for c in selected)
             + f" FROM access WHERE service IN ('{services}') ORDER BY client, service")

    for record in get_sqlite_db_records(file_found, query):
        client, service = record["client"], record["service"]
        raw_access = record[access_column]
        last_modified = _unix_ts(record["last_modified"]) if has_last_modified else ""
        svc = service.replace("kTCCService", "")
        access = _tcc_access_label(raw_access, has_auth_value)
        app = _app_entry(apps, client, client)
        app["perms"].append(f"{svc}: {access}" + (f" ({last_modified})" if last_modified else ""))
        app["sources"].add(Path(file_found).name)
        # No summary flag is raised just for holding a sensitive TCC permission:
        # mic/camera/photos/motion are common among benign apps, so flagging every
        # third-party app that holds one would flood the summary. The grant is still
        # reported, raw, in this detail table.


def _read_locationd_clients(file_found, apps, signals, key_traces):
    """Surface, per app, its location authorisation and background-location reach.

    locationd records an explicit grant in `Authorization` (sourced mapping at
    LOCATION_AUTH_STATUS), but an app's real reach is often expressed by
    `BackgroundLocationCapability` (the app can use location in the background) and
    an `SLC` dict (it is registered for significant-location-change monitoring).
    System location bundles (no BundleId) are surfaced only when they carry an
    explicit Authorization; real apps are surfaced on any of these signals.
    """
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    for client_key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        bundle_id = entry.get("BundleId", "")
        authorization = entry.get("Authorization")
        background_capable = entry.get("BackgroundLocationCapability") is True
        significant_change = isinstance(entry.get("SLC"), dict)

        bits = []
        if authorization is not None:
            bits.append(LOCATION_AUTH_STATUS.get(authorization, _format_value(authorization)))
        if bundle_id and background_capable:
            bits.append("background location capability")
        if bundle_id and significant_change:
            bits.append("significant-location-change monitoring")
        if not bits:
            continue
        if authorization is None and not bundle_id:
            continue  # system bundle with no explicit grant - not of interest here

        app = _app_entry(apps, bundle_id, str(client_key))
        app["perms"].append("Location: " + "; ".join(bits))
        app["sources"].add(Path(file_found).name)
        app["has_location"] = True

        # "Always" location (Authorization == 4) or a declared background-location
        # capability is unusual for a third-party (non-Apple) app and is the
        # behavioural signal we surface - whatever the app is.
        if (authorization == 4 or background_capable) and bundle_id and not bundle_id.startswith("com.apple"):
            signals.append((SEV_MEDIUM, "Third-party app has background/always location", bundle_id))
            key_traces.append(("Third-party app: background/always location", bundle_id))


def _collect_sensitive_permissions(files_found):
    apps, signals, sources, key_traces = {}, [], [], []
    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        if name == "tcc.db":
            sources.append(file_found)
            _read_tcc(file_found, apps)
        elif name == "clients.plist":
            sources.append(file_found)
            _read_locationd_clients(file_found, apps, signals, key_traces)

    # Order: apps with a location permission first, then the rest; each alphabetically.
    def sort_key(item):
        app = item[1]
        return (not app["has_location"], app["name"].lower())

    rows = []
    for _key, app in sorted(apps.items(), key=sort_key):
        rows.append((app["name"], app["bundle"], "; ".join(_dedupe(app["perms"])),
                     "; ".join(sorted(app["sources"]))))
    return rows, signals, _dedupe(sources), key_traces


@artifact_processor
def surveillance_sensitive_permissions(context):
    files_found = context.get_files_found()
    rows, _signals, sources, _traces = _collect_sensitive_permissions(files_found)
    return SENSITIVE_PERMISSIONS_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Category 3 - Account associations
# ===========================================================================

# "Association Type" is a high-level grouping so a reader can immediately tell
# what each row is about (a family circle, an iMessage account, location sharing,
# an identity lookup). "Origin" names the precise file/table the row came from.
ACCOUNT_ASSOCIATION_HEADERS = (
    "Association Type", "Identity / Account", "Role / Detail", "Origin", "Source File",
)

FAMILY_SHARING = "Family Sharing circle"
IMESSAGE_ACCOUNT = "iMessage / FaceTime account"
LOCATION_SHARING = "Find My / location sharing"
IDENTITY_LOOKUP = "Identity lookup cache"


def _iter_family_members(obj, seen=None):
    """Yield distinct family-member dicts found anywhere in a plist structure.

    Works for both CircleCache.plist and the NSKeyedArchiver-encoded
    familyCircleCache (whose object graph repeats each member). Members are
    identified by the presence of 'member-apple-id' and de-duplicated.
    """
    if seen is None:
        seen = set()
    if isinstance(obj, dict):
        if "member-apple-id" in obj:
            key = (obj.get("member-apple-id"), str(obj.get("member-join-date-epoch")),
                   str(obj.get("member-dsid-hash")))
            if key not in seen:
                seen.add(key)
                yield obj
        else:
            for value in obj.values():
                yield from _iter_family_members(value, seen)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_family_members(item, seen)


def _read_circlecache(file_found, rows, signals, key_traces):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    origin = Path(file_found).name
    others = 0
    for member in _iter_family_members(data):
        apple_id = member.get("member-apple-id", "")
        is_me = member.get("is-me", False)
        role = []
        if is_me:
            role.append("device owner")
        if member.get("member-is-organizer"):
            role.append("organizer")
        if member.get("member-is-parent-account"):
            role.append("parent")
        detail = [f"role={', '.join(role) if role else 'member'}",
                  f"name={member.get('member-first-name', '')} {member.get('member-last-name', '')}".strip()]
        if member.get("member-phone-numbers"):
            detail.append(f"phone={member.get('member-phone-numbers')}")
        if member.get("member-join-date-epoch"):
            detail.append(f"joined={_unix_ts(member.get('member-join-date-epoch'))}")
        rows.append((FAMILY_SHARING, apple_id, "; ".join(p for p in detail if p),
                     origin, file_found))
        if apple_id:
            key_traces.append(("Family Sharing account",
                               f"{apple_id} ({', '.join(role) if role else 'member'})"))
        if not is_me:
            others += 1
            if member.get("member-is-organizer") or member.get("member-is-parent-account"):
                signals.append((SEV_MEDIUM, "Family circle controlled by another account",
                                f"{apple_id} ({', '.join(role)})"))
    if others:
        signals.append((SEV_MEDIUM, "Device belongs to a family circle with other members",
                        f"{others} other member(s)"))


def _read_jfamilycircle(file_found, rows, signals, key_traces):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    members = (((data.get("circle") or {}).get("family") or {}).get("members")) or []
    for member in members:
        if not isinstance(member, dict):
            continue
        account = member.get("accountName", "")
        detail = f"name={member.get('firstName', '')} {member.get('lastName', '')}".strip()
        detail += f"; dsid={member.get('ICloudDsid', '')}"
        rows.append((FAMILY_SHARING, account, detail,
                     "JFamilyCircle.plist", file_found))
        if account:
            key_traces.append(("Family Sharing account", account))


def _read_rm_admin_store(file_found, rows, signals, key_traces):
    selected, db_rows = _fetch_existing_columns(
        file_found, "ZCOREUSER",
        ["ZAPPLEID", "ZDSID", "ZALTDSID", "ZISFAMILYORGANIZER", "ZISPARENT",
         "ZFAMILYMEMBERTYPE", "ZGIVENNAME", "ZFAMILYNAME"])
    for row in db_rows:
        details = {c: _format_value(row[c]) for c in selected}
        apple_id = details.get("ZAPPLEID", "")
        rows.append((FAMILY_SHARING, apple_id,
                     json.dumps(details, ensure_ascii=False),
                     "RMAdminStore-Local.sqlite (ZCOREUSER)", file_found))
        if apple_id:
            key_traces.append(("Family account (remote management store)", apple_id))


def _read_transparency_model(file_found, rows, signals, key_traces):
    selected, db_rows = _fetch_existing_columns(
        file_found, "ZPEERSTATE", ["ZAPPLICATION", "ZURI", "ZOPTEDIN", "ZSEENDATE", "ZEVEROPTEDIN"])
    for row in db_rows:
        uri = _format_value(row["ZURI"]) if "ZURI" in selected else ""
        if not uri:
            continue
        seen = _coredata_ts(row["ZSEENDATE"]) if "ZSEENDATE" in selected and row["ZSEENDATE"] else ""
        application = _format_value(row["ZAPPLICATION"]) if "ZAPPLICATION" in selected else ""
        rows.append((IMESSAGE_ACCOUNT, uri, f"application={application}; seen={seen}",
                     "TransparencyModel.sqlite (ZPEERSTATE)", file_found))
        key_traces.append(("iMessage / FaceTime account", uri))


def _read_idstatuscache(file_found, rows, signals, key_traces):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    labels = {
        "com.apple.private.alloy.fmf": "Find My Friends (location sharing)",
        "com.apple.private.alloy.fmd": "Find My Device",
        "com.apple.private.alloy.nearby": "Find My / nearby",
        "com.apple.private.alloy.screentime": "Screen Time",
        "com.apple.private.alloy.digitalhealth": "Screen Time (digital health)",
    }
    location_services = ("com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd",
                         "com.apple.private.alloy.nearby")
    for service, entries in data.items():
        if not isinstance(entries, dict) or not entries:
            continue
        label = labels.get(service, service)
        association = LOCATION_SHARING if service in location_services else IDENTITY_LOOKUP
        for identity, status in entries.items():
            lookup = _coredata_ts(status.get("LookupDate")) if isinstance(status, dict) else ""
            rows.append((association, identity, f"{label}; lookup={lookup}",
                         "idstatuscache.plist", file_found))
            if service in ("com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd"):
                signals.append((SEV_MEDIUM, "Location-sharing identity present", f"{identity} via {label}"))
                key_traces.append(("Location-sharing identity", f"{identity} ({label})"))


def _read_identity_lookup_tsv(file_found, rows, signals, key_traces):
    for number, line in enumerate(_read_text_lines(file_found), start=1):
        if number == 1 and "Partner" in line:
            continue
        if any(t in line.lower() for t in ("imessage", "facetime", "icloud", "x-apple", "mailto")):
            rows.append((IDENTITY_LOOKUP, "", _short_text(line),
                         f"Identity Lookup Service.tsv (line {number})", file_found))


def _collect_account_associations(files_found):
    rows, signals, sources, key_traces = [], [], [], []
    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        reader = {
            "circlecache.plist": _read_circlecache,
            "familycirclecache": _read_circlecache,
            "jfamilycircle.plist": _read_jfamilycircle,
            "rmadminstore-local.sqlite": _read_rm_admin_store,
            "transparencymodel.sqlite": _read_transparency_model,
            "idstatuscache.plist": _read_idstatuscache,
        }.get(name)
        if reader is None and name.endswith(".tsv"):
            reader = _read_identity_lookup_tsv
        if reader is None:
            continue
        sources.append(file_found)
        reader(file_found, rows, signals, key_traces)
    return rows, signals, _dedupe(sources), key_traces


@artifact_processor
def surveillance_account_associations(context):
    files_found = context.get_files_found()
    rows, _signals, sources, _traces = _collect_account_associations(files_found)
    return ACCOUNT_ASSOCIATION_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Category 4 - Pairing and backup traces
# ===========================================================================

PAIRING_BACKUP_HEADERS = (
    "Record Type", "Identifier / Field", "Value", "Context", "Source File",
)


def _read_lockdown_pairing(file_found, rows, signals, host_names):
    """Extract handle_pair host identifiers and backup-host set events."""
    lines = _read_text_lines(file_found)
    imazing_seen = False
    ts_re = re.compile(r"^(?P<ts>\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    prepare_re = re.compile(r"handle_pair:\s*Preparing to pair for\s+(?P<actor>.+?)\s*\.")
    field_re = re.compile(r'^\s*(?P<key>HostName|SystemBUID|HostID|MarketingName)\s*=\s*"?(?P<val>[^";]+)"?')
    set_re = re.compile(
        r"handle_set_value:\s*(?P<actor>.+?)\s+attempting to set "
        r"\[(?P<domain>[^\]]*)\]:\[(?P<key>[^\]]+)\]\s+to\s+\[(?P<value>[^\]]*)\]", re.IGNORECASE)
    trust_re = re.compile(r"handle_is_host_trusted:\s*Host client\s+(?P<client>\S+)\s+is trusted", re.IGNORECASE)
    amb_re = re.compile(r"AppleMobileBackup\s+attempting to spawn\s+com\.apple\.mobilebackup", re.IGNORECASE)
    interesting_set_keys = {"LastBackupComputerName", "LastBackupComputerType",
                            "LastiTunesBackupDate", "HostName", "SystemBUID"}
    seen_pair = set()
    seen_misc = set()
    current_actor = current_ts = ""
    in_block = False
    depth = 0
    block = {}

    def emit(block):
        key = (block.get("SystemBUID"), block.get("HostName"), block.get("actor"))
        if key in seen_pair:
            return
        seen_pair.add(key)
        if block.get("HostName"):
            host_names.add(block["HostName"])
        detail = "; ".join(f"{k}={block[k]}" for k in ("HostName", "MarketingName", "SystemBUID", "HostID") if k in block)
        rows.append(("Pairing request (handle_pair)", block.get("actor", ""), detail,
                     f"@ {block.get('timestamp', '')}", file_found))

    for line in lines:
        ts_match = ts_re.match(line)
        if ts_match:
            current_ts = ts_match.group("ts")
        prepare = prepare_re.search(line)
        if prepare:
            current_actor = prepare.group("actor").strip()
            if "imazing" in current_actor.lower():
                imazing_seen = True

        if not in_block and "handle_pair: Pair message: {" in line:
            in_block = True
            depth = 1
            block = {"timestamp": current_ts, "actor": current_actor}
            continue

        if in_block:
            field = field_re.match(line)
            if field and field.group("key") not in block:
                block[field.group("key")] = field.group("val").strip()
            # Track brace depth so certificate lines containing '}' do not end
            # the block prematurely.
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_block = False
                emit(block)
            continue

        set_match = set_re.search(line)
        if set_match and set_match.group("key") in interesting_set_keys:
            key = set_match.group("key")
            value = set_match.group("value").strip()
            if key == "LastiTunesBackupDate":
                value = _coredata_ts(value)
            if key in ("LastBackupComputerName", "HostName") and value:
                host_names.add(value)
            rows.append(("Lockdown value set by host", f"{set_match.group('actor').strip()} -> {key}",
                         value, f"@ {current_ts}", file_found))
            continue

        trust = trust_re.search(line)
        if trust:
            client = trust.group("client")
            if ("trust", client) not in seen_misc:
                seen_misc.add(("trust", client))
                rows.append(("Host trusted", "handle_is_host_trusted", client, f"@ {current_ts}", file_found))
            continue

        if amb_re.search(line) and "amb" not in seen_misc:
            seen_misc.add("amb")
            rows.append(("Backup service spawned", "AppleMobileBackup -> com.apple.mobilebackup2",
                         "Finder / AppleMobileBackup backup", f"@ {current_ts}", file_found))
            signals.append((SEV_MEDIUM, "Finder / AppleMobileBackup backup performed",
                            "lockdown.log AppleMobileBackup spawn"))
    return imazing_seen


def _read_pair_record(file_found, rows, host_names):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    if data.get("HostName"):
        host_names.add(data["HostName"])
    detail = [f"{k}={data[k]}" for k in ("HostID", "SystemBUID", "HostName", "SerialNumber") if data.get(k)]
    if data.get("WallTimeWhenCreated"):
        detail.append(f"created={_unix_ts(data['WallTimeWhenCreated'])}")
    rows.append(("Pair record", Path(file_found).stem, "; ".join(detail), "pair_records", file_found))


def _read_backup_info(file_found, rows):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    for key in ("Device Name", "Product Version", "Serial Number", "IMEI", "Phone Number",
                "Target Identifier", "GUID", "Last Backup Date", "iTunes Version", "Product Type"):
        if key in data:
            value = _plist_ts(data[key]) if key == "Last Backup Date" else _short_text(data[key])
            event = "Current backup date" if key == "Last Backup Date" else "Backup device metadata"
            rows.append((event, key, value, "backup Info.plist", file_found))


def _read_data_ark(file_found, rows, host_names):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    interesting = {
        "com.apple.iTunes.backup-LastBackupComputerName": "Last backup computer name",
        "com.apple.iTunes.backup-LastBackupComputerType": "Last backup computer type",
        "com.apple.mobile.backup-LastiTunesBackupDate": "Last iTunes backup date",
        "com.apple.mobile.backup-LastiTunesBackupTZ": "Last iTunes backup TZ",
        "com.apple.mobile.backup-WillEncrypt": "Backup encryption enabled",
        "-DeviceName": "Device name",
    }
    for key, label in interesting.items():
        if key not in data:
            continue
        value = _coredata_ts(data[key]) if key == "com.apple.mobile.backup-LastiTunesBackupDate" else _short_text(data[key])
        rows.append(("Lockdown data_ark", label, value, key, file_found))
        if "ComputerName" in key and data[key]:
            host_names.add(str(data[key]))


def _read_atc(file_found, rows, host_names):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    for kp, key, value in _iter_plist_values(data, {"LibraryID", "SyncHostName", "HostName"}):
        rows.append(("Sync host / library", key, _short_text(value), kp, file_found))
        if "host" in key.lower() and isinstance(value, str):
            host_names.add(value)


def _collect_pairing_backup(files_found):
    rows, signals, sources, key_traces = [], [], [], []
    host_names = set()
    pair_record_count = 0
    imazing_seen = False

    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        path_norm = str(file_found).replace("\\", "/")

        if name in ("lockdownd.log", "lockdownd.log.1", "lockdown.log", "lockdown.log.1"):
            sources.append(file_found)
            imazing_seen = _read_lockdown_pairing(file_found, rows, signals, host_names) or imazing_seen
        elif name.endswith(".plist") and "pair_records" in path_norm:
            sources.append(file_found)
            _read_pair_record(file_found, rows, host_names)
            pair_record_count += 1
        elif name == "info.plist":
            sources.append(file_found)
            _read_backup_info(file_found, rows)
        elif name == "com.apple.atc.plist":
            sources.append(file_found)
            _read_atc(file_found, rows, host_names)
        elif name == "data_ark.plist":
            sources.append(file_found)
            _read_data_ark(file_found, rows, host_names)
        elif name == "com.apple.ldbackup.plist":
            data = get_plist_file_content(file_found)
            if isinstance(data, dict):
                sources.append(file_found)
                for key in ("LastiTunesBackupDate", "LastCloudBackupDate"):
                    if key in data:
                        rows.append(("Previous backup date", key, _coredata_ts(data[key]), "ldbackup", file_found))
        elif name == "com.apple.mobilebackup.plist":
            data = get_plist_file_content(file_found)
            if isinstance(data, dict):
                # FetchMissingKeysAtNextUnlock is noise and is discarded.
                useful = {k: v for k, v in data.items() if k != "FetchMissingKeysAtNextUnlock"}
                if useful:
                    sources.append(file_found)
                    for key, value in useful.items():
                        rows.append(("Backup preference", key, _format_value(value), "MobileBackup", file_found))

    host_names = {h for h in host_names if h}
    if host_names:
        signals.append((SEV_MEDIUM if len(host_names) > 1 else SEV_INFO,
                        "Device paired with computer(s)", "trusted host(s): " + ", ".join(sorted(host_names))))
        for host in sorted(host_names):
            key_traces.append(("Paired computer", host))
    if imazing_seen:
        signals.append((SEV_MEDIUM, "Third-party backup tool (iMazing) paired", "lockdownd.log handle_pair"))
        key_traces.append(("Third-party pairing tool", "iMazing"))
    if pair_record_count:
        signals.append((SEV_MEDIUM if pair_record_count > 1 else SEV_INFO,
                        "Pairing record(s) present", f"{pair_record_count} pair record(s)"))
    return rows, signals, _dedupe(sources), key_traces


@artifact_processor
def surveillance_pairing_backup(context):
    files_found = context.get_files_found()
    rows, _signals, sources, _traces = _collect_pairing_backup(files_found)
    return PAIRING_BACKUP_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Unified logs (Apple Unified Logs, via forensic_aul) - shared infrastructure
# ===========================================================================
#
# The four categories above read static files. The unified logs add the temporal
# dimension (when a backup ran, when a computer was connected). They are parsed
# with the forensic_aul library into a normalised SQLite database; the unified-log
# artifacts then SELECT the events they want out of it.
#
# Design (per the project rules - reuse the library, no interpretation, one file):
#   * Two acquisition shapes: a sysdiagnose `system_logs.logarchive`, or an FFS's
#     loose `var/db/diagnostics` + `var/db/uuidtext` (fed to forensic_aul as a
#     mapping). See `_get_unified_log_db`.
#   * Parse ONCE per run: the database is written to the run output folder
#     (`_aul_db_path`) and every unified-log artifact checks for it before
#     parsing, so the heavy parse is shared, not repeated per artifact. A new run
#     re-parses (a fresh output folder).
#   * Progress is streamed to the iLEAPP terminal during the long parse phase
#     (`_aul_progress_sink`).
#   * Events are matched by `_aul_query` with simple "signatures" - an invariant
#     format string where one exists, or a clean-message prefix for the dynamic
#     launchd lines that have none - and reported almost verbatim.
#
# Key caveat encoded in the output: unified-log entries roll off after a limited
# retention (~14 days for backup events), so a missing event is NOT proof that a
# backup never happened.

UNIFIED_LOG_BACKUP_HEADERS = (
    ("Timestamp", "datetime"), "Event", "Detail", "Source",
)

# Only LOCAL backups are reported: a computer connected and ran BackupAgent2
# through the lockdown service com.apple.mobilebackup2. That is the surveillance-
# relevant case (someone with physical access copied the device). iCloud backups
# (backupd / com.apple.mobilebackup - the device's own routine) are deliberately
# NOT reported here; their "Starting backup" / "Backup starting" lines come from a
# different daemon and are out of scope for this artifact.
#
# Detection is by MESSAGE text scoped to the mobilebackup2 subsystem, not by
# process name: in a sysdiagnose logarchive the process image is unresolved
# (forensic_aul stores the process UUID), so the readable daemon identity instead
# appears in the subsystem field (e.g. "com.apple.mobilebackup2", "[BackupAgent2]").
# A local backup session BEGINS when mobilebackup2 spawns BackupAgent2 and ENDS
# when that service exits ("ran for Nms" gives the exact duration). The generic
# launchd exit line is scoped to the mobilebackup2 subsystem so it can only match a
# BackupAgent2 session - never backupd / iCloud.
#
# These launchd lifecycle lines carry NO unified-log format string (verified on
# the real device: format_str is NULL), so the only handle is the already-clean
# `message` column. Events are therefore identified by exact message prefixes
# (SQL LIKE, in the query) and the few values (pid, duration) are pulled out with
# plain string slicing - no regex, and no timestamp/metadata to strip because the
# message column is already just the message.
_BACKUP_START_PREFIX = "Successfully spawned BackupAgent2["
_BACKUP_FINISH_PREFIX = "exited due to exit("


def _str_between(text, start, end):
    """Return the substring between the first `start` and the following `end`."""
    if start not in text:
        return ""
    rest = text.split(start, 1)[1]
    return rest.split(end, 1)[0] if end in rest else ""

# Observed empirical retention of backup events in the unified logs (this
# research). Stated next to every result so "not found" is read correctly.
AUL_BACKUP_RETENTION_NOTE = (
    "Unified-log backup events persist only ~14 days; the absence of an event is "
    "not proof that a backup never happened."
)

# forensic_aul parser process budget. The result is identical for any value
# (ordering is assigned post-load); higher = faster on multi-core machines.
AUL_EXTRACT_JOBS = 4


def _aul_db_path(report_folder):
    """The shared unified-log database path for this run.

    The database is written ONCE per analysis into the run's output folder and
    every unified-log artifact uses this same path: each one checks whether the
    file already exists before parsing, so the (heavy) parse happens once per run,
    not once per artifact. `report_folder` is `<base>/_HTML/<Category>`, so the run
    base is two levels up (mirrors ilapfuncs.tsv()); the DB lives beside the
    report, not under a category, so any category's artifacts share it.
    """
    base = Path(report_folder).resolve().parents[1]
    return base / "_unified_logs" / "aul_unified_logs.db"


def _find_logarchive_root(files_found):
    """Return the `system_logs.logarchive` directory (sysdiagnose), or None.

    The artifact's path glob copies the whole logarchive bundle into the report
    data folder preserving its structure; any matched file inside it lets us
    recover the bundle root, which is what forensic_aul parses.
    """
    marker = "system_logs.logarchive"
    for file_found in files_found:
        norm = str(file_found).replace("\\", "/")
        idx = norm.find(marker)
        if idx != -1:
            root = norm[: idx + len(marker)]
            if Path(root).is_dir():
                return root
    return None


def _find_loose_dirs(files_found):
    """Return (diagnostics_dir, uuidtext_dir) recovered from FFS matched files.

    A full file system extraction has no `.logarchive`; it carries the two loose
    on-device folders `private/var/db/diagnostics` (tracev3 material) and
    `private/var/db/uuidtext` (format-string tables). forensic_aul accepts those
    two as a `{"diagnostics": ..., "uuidtext": ...}` mapping. Returns None unless
    BOTH are present.
    """
    diagnostics = uuidtext = None
    for file_found in files_found:
        norm = str(file_found).replace("\\", "/")
        for marker, is_diag in (("/var/db/diagnostics", True), ("/var/db/uuidtext", False)):
            idx = norm.find(marker)
            if idx != -1:
                root = norm[: idx + len(marker)]
                if Path(root).is_dir():
                    if is_diag:
                        diagnostics = root
                    else:
                        uuidtext = root
    if diagnostics and uuidtext:
        return diagnostics, uuidtext
    return None


def _aul_progress_sink():
    """A forensic_aul progress sink that prints checkpoints to the iLEAPP terminal.

    Parsing the unified logs is the long step; forensic_aul reports progress
    within the parse phase (from the main process, even with several workers), so
    these lines confirm the run is advancing and not stuck.
    """
    state = {"last_pct": -1, "last_phase": None}

    def sink(event):
        pct = int(event.overall * 100)
        # Emit on the first event, on every phase change (so the slow "prepare"
        # -> "parse" transition is visible and the run never looks stuck on
        # hashing), and on each 10% step thereafter.
        if (state["last_pct"] < 0 or event.phase != state["last_phase"]
                or pct >= state["last_pct"] + 10 or pct >= 100):
            state["last_pct"] = pct
            state["last_phase"] = event.phase
            detail = f" ({event.detail})" if event.detail else ""
            logfunc(f"    unified logs: {pct:3d}%  {event.phase}{detail}")

    return sink


def _extract_unified_logs(source, db_path):
    """Parse `source` into a forensic_aul SQLite database at `db_path`.

    `source` is either a `system_logs.logarchive` path (sysdiagnose) or a
    `{"diagnostics": dir, "uuidtext": dir}` mapping (FFS) - run_extract prepares
    either form itself. Returns `db_path`, or None (after logging) if the library
    is unavailable or extraction fails - the artifact then yields no rows rather
    than breaking the run.
    """
    try:
        from forensic_aul import run_extract
    except ImportError:
        logfunc("Surveillance: forensic_aul is not installed - skipping the "
                "unified-log artifacts. Install scripts/faul_lib (pip install -e .) "
                "to enable them.")
        return None

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        logfunc("Surveillance: parsing the Apple Unified Logs (the long step - a few "
                "minutes; progress below)...")
        run_extract(
            source if isinstance(source, dict) else Path(source),
            db_path,
            case_number="iLEAPP-Surveillance",
            jobs=AUL_EXTRACT_JOBS,
            overwrite=True,
            # We query by indexed columns (format string / subsystem), never
            # full-text, so skip the FTS5 build over millions of rows. fast_write
            # trades crash-durability for speed (this is a throwaway analysis DB).
            fts=False,
            fast_write=True,
            work_dir=db_path.parent,           # same FS: FFS loose-dirs can hard-link
            progress=_aul_progress_sink(),
        )
        logfunc("Surveillance: unified-log parsing complete.")
    except Exception as ex:  # noqa: BLE001 - never let extraction abort the run
        logfunc(f"Surveillance: forensic_aul extraction failed ({ex}); "
                "no unified-log events parsed.")
        return None
    return db_path


def _get_unified_log_db(files_found, report_folder):
    """Return (db_path, source_label) for this run's shared unified-log database.

    Parse-once-per-run: if the database already exists in the run output folder it
    is reused; otherwise the sysdiagnose logarchive, or the FFS diagnostics +
    uuidtext folders, are parsed into it. Returns (None, None) when neither source
    is present or forensic_aul is unavailable / fails.
    """
    logarchive_root = _find_logarchive_root(files_found)
    loose = None if logarchive_root else _find_loose_dirs(files_found)
    if not logarchive_root and not loose:
        return None, None
    source_label = logarchive_root or "diagnostics + uuidtext (FFS)"

    db_path = _aul_db_path(report_folder)
    if db_path.exists():                      # already parsed earlier in this run
        return db_path, source_label

    source = (logarchive_root if logarchive_root
              else {"diagnostics": Path(loose[0]), "uuidtext": Path(loose[1])})
    if _extract_unified_logs(source, db_path):
        return db_path, source_label
    return None, None


# A unified-log "signature" identifies an event WITHOUT regex: either by the
# invariant format string (the f-string template, when the message has one) or -
# for dynamic / generic messages that have none, like the launchd backup lines -
# by an exact message prefix, optionally scoped to a subsystem:
#     {"format_str": "<exact format_strs.value>"}
#     {"message_prefix": "<text>", "subsystem_like": "%mobilebackup2%"}   # subsystem optional
# `_aul_query` turns a list of these into one SELECT and returns the matched rows
# (ts, subsystem, message) - the building block every unified-log artifact uses.

def _like_escape(text):
    """Escape a literal for a SQLite LIKE pattern (so % and _ are not wildcards)."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _aul_query(db_path, signatures):
    """Select unified-log rows matching any of the given signatures (no regex)."""
    import sqlite3

    clauses, params = [], []
    for sig in signatures:
        if "format_str" in sig:
            clauses.append("l.format_str_id IN (SELECT id FROM format_strs WHERE value = ?)")
            params.append(sig["format_str"])
        elif "message_prefix" in sig:
            clause = "l.message LIKE ? ESCAPE '\\'"
            params.append(_like_escape(sig["message_prefix"]) + "%")
            if sig.get("subsystem_like"):
                clause = "(" + clause + " AND s.name LIKE ?)"
                params.append(sig["subsystem_like"])
            clauses.append(clause)
    if not clauses:
        return []

    sql = ("SELECT l.timestamp_unix_ns AS ts, s.name AS subsystem, l.message AS message "
           "FROM logs l LEFT JOIN subsystems s ON l.subsystem_id = s.id "
           "WHERE " + " OR ".join(clauses) + " ORDER BY l.timestamp_unix_ns")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _aul_archive_span(db_path):
    """Return (log_start_time, log_end_time) from the database, or (None, None)."""
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT log_start_time, log_end_time FROM case_metadata LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (None, None)
    finally:
        conn.close()


def _query_backup_events(db_path):
    """Read local (BackupAgent2 / mobilebackup2) backup events from the database.

    Only the LOCAL backup path is read - iCloud (backupd) events are excluded by
    construction (the generic launchd exit line is scoped to the mobilebackup2
    subsystem, so it can only match a BackupAgent2 session, never backupd). These
    launchd lines are dynamic (no format string), so they are matched on the clean
    `message` column. Returns a list of event dicts:
        ts        raw nanosecond timestamp
        kind      'start' | 'finish'
        duration  session length in seconds (finish only; exact 'ran for Nms')
        pid       BackupAgent2 pid
    """
    rows = _aul_query(db_path, [
        {"message_prefix": _BACKUP_START_PREFIX},
        {"message_prefix": _BACKUP_FINISH_PREFIX, "subsystem_like": "%mobilebackup2%"},
    ])
    events = []
    for r in rows:
        msg, subsys = r["message"] or "", r["subsystem"] or ""
        # Start: "Successfully spawned BackupAgent2[<pid>] because ipc (mach)".
        if msg.startswith(_BACKUP_START_PREFIX):
            events.append({"ts": r["ts"], "kind": "start", "duration": None,
                           "pid": _str_between(msg, "BackupAgent2[", "]")})
        # Finish: "exited due to exit(<code>), ran for <ms>ms". The pid is in the
        # subsystem name, e.g. "user/501/com.apple.mobilebackup2 [553]".
        elif msg.startswith(_BACKUP_FINISH_PREFIX) and "ran for" in msg and "mobilebackup2" in subsys:
            ms_text = _str_between(msg, "ran for ", "ms").strip()
            duration = round(int(ms_text) / 1000, 1) if ms_text.isdigit() else None
            events.append({"ts": r["ts"], "kind": "finish", "duration": duration,
                           "pid": _str_between(subsys, "[", "]") or None})
    return events


def _collect_unified_log_backups(files_found, report_folder):
    """Parse the unified logs and build the backup-event rows.

    Returns (rows, sources). Empty when there is no logarchive in the input or
    forensic_aul is unavailable / fails.
    """
    db_path, source = _get_unified_log_db(files_found, report_folder)
    if not db_path:
        return [], []

    events = _query_backup_events(db_path)
    rows = []

    # Context banner: the window the logs actually cover, then the retention note.
    span_start, span_end = _aul_archive_span(db_path)
    if span_start or span_end:
        rows.append(("", "Archive time span",
                     f"{span_start or '?'} to {span_end or '?'} (UTC); events outside "
                     "this window are not available", source))
    rows.append(("", "Retention note", AUL_BACKUP_RETENTION_NOTE, source))

    if not events:
        rows.append(("", "No backup events found",
                     "No local (BackupAgent2 / com.apple.mobilebackup2) backup "
                     "sessions in the available window. " + AUL_BACKUP_RETENTION_NOTE,
                     source))
        return rows, [source]

    starts = [e for e in events if e["kind"] == "start"]

    # One row per observed local backup event (raw, dated). Duration is the
    # logged 'ran for Nms' - a fact, not an inference.
    for ev in events:
        if ev["kind"] == "start":
            event_name = "Local backup started"
            detail = (f"BackupAgent2 spawned (pid {ev['pid']}) via "
                      "com.apple.mobilebackup2 - a computer was connected")
        else:
            event_name = "Local backup finished"
            detail = f"ran {ev['duration']} s" if ev["duration"] is not None else ""
            if ev["pid"]:
                detail = (detail + f" (pid {ev['pid']})") if detail else f"pid {ev['pid']}"
        rows.append((convert_unix_ts_to_utc(ev["ts"]), event_name, detail, source))

    # Factual count of the sessions in the available window.
    rows.append(("", "Backup count (available window)",
                 f"{len(starts)} local (computer) backup session(s) "
                 "(iCloud/backupd backups are not counted)", source))

    return rows, [source]


@artifact_processor
def surveillance_unified_log_backups(context):
    files_found = context.get_files_found()
    rows, sources = _collect_unified_log_backups(files_found, context.get_report_folder())
    return UNIFIED_LOG_BACKUP_HEADERS, rows, "; ".join(sources)


# ===========================================================================
# Unified-log paired-computer presence (companion-link / Rapport)
# ===========================================================================
# When a trusted computer is near or connected, iOS discovers it over
# companion-link (Continuity) and logs it BY NAME with its hardware addresses and
# the transport used (USB / Bluetooth LE / Wi-Fi). This dates when a specific
# named computer was physically present - which the static pairing records cannot
# - and usually brackets a local backup. On iOS 17.5.1 the 'atc' transport daemon
# does NOT log the sync host to the unified logs (only its own lifecycle), so this
# companion-link discovery is the usable unified-log source for "which computer,
# when". As with the backup events, identification is by exact message prefix on
# the already-clean `message` column and values are pulled out with plain string
# slicing - no regex.

UNIFIED_LOG_COMPANION_HEADERS = (
    ("Timestamp", "datetime"), "Computer", "Transport", "Detail", "Source",
)

AUL_COMPANION_NOTE = (
    "Companion-link presence shows when a trusted computer was near / connected "
    "(USB / Bluetooth LE / Wi-Fi). Like all unified-log events it has a limited "
    "retention, so the absence of an event is not proof a computer was never present."
)


def _parse_companion_message(msg):
    """Return {event, computer, transport, address} from a companion-link message.

    Plain string slicing on the clean message - no regex. Handles the rapport
    "Bonjour unauth peer found/lost ..." lines (the found line also carries the
    transport, e.g. "TT 0x8 < USB >") and the CoreUtils "CLink: Found/Lost
    CUBonjourDevice <addr>, '<name>'" lines.
    """
    if "peer found" in msg:
        return {"event": "found",
                "computer": _str_between(msg, '"', '"'),
                "transport": _str_between(msg, "< ", " >"),
                "address": _str_between(msg, "BLE Address: <", ">")}
    if "peer lost" in msg:
        return {"event": "lost",
                "computer": _str_between(msg, "'", "'"),
                "transport": "",
                "address": _str_between(msg, "lost <", ">")}
    if msg.startswith("CLink: Found") or msg.startswith("CLink: Lost"):
        return {"event": "found" if msg.startswith("CLink: Found") else "lost",
                "computer": _str_between(msg, "'", "'"),
                "transport": "",
                "address": _str_between(msg, "CUBonjourDevice ", ",")}
    return None


def _query_companion_events(db_path):
    """Read companion-link found/lost events (rapport + CoreUtils) from the DB."""
    rows = _aul_query(db_path, [
        {"message_prefix": "Bonjour unauth peer found", "subsystem_like": "com.apple.rapport"},
        {"message_prefix": "Bonjour unauth peer lost", "subsystem_like": "com.apple.rapport"},
        {"message_prefix": "CLink: Found CUBonjourDevice", "subsystem_like": "com.apple.CoreUtils"},
        {"message_prefix": "CLink: Lost CUBonjourDevice", "subsystem_like": "com.apple.CoreUtils"},
    ])
    events = []
    for r in rows:
        parsed = _parse_companion_message(r["message"] or "")
        if parsed and parsed["computer"]:
            parsed["ts"] = r["ts"]
            events.append(parsed)
    return events


def _collect_unified_log_companion(files_found, report_folder):
    """Build the paired-computer-presence rows from the unified logs.

    Returns (rows, sources). Empty when there is no logarchive or forensic_aul is
    unavailable / fails.
    """
    db_path, logarchive_root = _get_unified_log_db(files_found, report_folder)
    if not db_path:
        return [], []

    events = _query_companion_events(db_path)
    source = logarchive_root
    rows = [("", "", "", AUL_COMPANION_NOTE, source)]

    if not events:
        rows.append(("", "", "", "No companion-link computer discovery in the "
                     "available window. " + AUL_COMPANION_NOTE, source))
        return rows, [source]

    # rapport and CoreUtils both log the same found/lost within the same second;
    # keep one per (computer, event, second), preferring the row with a transport.
    best = {}
    for ev in events:
        key = (ev["computer"], ev["event"], ev["ts"] // 1_000_000_000)
        cur = best.get(key)
        if cur is None or (not cur["transport"] and ev["transport"]):
            best[key] = ev
    deduped = sorted(best.values(), key=lambda e: e["ts"])

    # Per-computer summary: first/last seen, transports and addresses observed.
    summary = {}
    for ev in deduped:
        s = summary.setdefault(ev["computer"],
                               {"first": ev["ts"], "last": ev["ts"],
                                "transports": set(), "addresses": set(), "count": 0})
        s["first"] = min(s["first"], ev["ts"])
        s["last"] = max(s["last"], ev["ts"])
        s["count"] += 1
        if ev["transport"]:
            s["transports"].add(ev["transport"])
        if ev["address"]:
            s["addresses"].add(ev["address"])

    for computer, s in sorted(summary.items()):
        transports = ", ".join(sorted(s["transports"])) or "unspecified"
        detail = (f"present: first seen {convert_unix_ts_to_utc(s['first'])} -> "
                  f"last seen {convert_unix_ts_to_utc(s['last'])} "
                  f"({s['count']} discovery event(s)); addresses: "
                  + (", ".join(sorted(s["addresses"])) or "n/a"))
        rows.append((convert_unix_ts_to_utc(s["first"]), computer, transports, detail, source))

    # One row per discovery event (deduped), newest evidence kept verbatim.
    for ev in deduped:
        detail = f"companion-link peer {ev['event']}"
        if ev["address"]:
            detail += f" (address {ev['address']})"
        rows.append((convert_unix_ts_to_utc(ev["ts"]), ev["computer"],
                     ev["transport"], detail, source))

    return rows, [source]


@artifact_processor
def surveillance_unified_log_companion(context):
    files_found = context.get_files_found()
    rows, sources = _collect_unified_log_companion(files_found, context.get_report_folder())
    return UNIFIED_LOG_COMPANION_HEADERS, rows, "; ".join(sources)


# ===========================================================================
# Summary - roll-up of the most important traces (no severity / no verdict)
# ===========================================================================

SUMMARY_HEADERS = ("Category", "Trace", "Detail", "Verify in")

# Each summary category and the detail artifact whose page holds the full
# context for its traces. The collector supplies the key traces.
_SUMMARY_CATEGORIES = (
    ("Remote management", "surveillance_remote_management", _collect_remote_management),
    ("Sensitive permissions", "surveillance_sensitive_permissions", _collect_sensitive_permissions),
    ("Account associations", "surveillance_account_associations", _collect_account_associations),
    ("Pairing & backup", "surveillance_pairing_backup", _collect_pairing_backup),
)


def _detail_page_filename(artifact_key):
    """Final HTML filename iLEAPP gives a detail artifact's report page.

    iLEAPP writes every artifact page flat into the report's _HTML/ folder, named
    after the artifact's display name with spaces replaced by underscores (see
    scripts/report.py). The summary page lives in the same folder, so a bare
    relative href to a sibling page works.
    """
    return __artifacts_v2__[artifact_key]["name"].replace(" ", "_") + ".html"


def _detail_page_link(artifact_key):
    """An HTML anchor to a detail artifact's page (for the 'Verify in' column)."""
    name = __artifacts_v2__[artifact_key]["name"]
    href = _detail_page_filename(artifact_key)
    return f'<a href="{html.escape(href, quote=True)}">{html.escape(name)}</a>'


@artifact_processor
def surveillance_summary(context):
    """Roll up the most important concrete traces from the four categories.

    This artifact states facts only - it assigns no severity and no verdict. It
    lists the salient identifiers (accounts, MDM enrolment, MDM-managed apps,
    third-party apps with background/always location, paired computers, ...) and
    links each one, via the 'Verify in' column, to the detail page that holds its
    full context.

    Output is returned as a (tsv_rows, html_rows) tuple so the link markup
    appears only in the HTML report; the TSV export keeps a plain page name.
    """
    files_found = context.get_files_found()
    tsv_rows, html_rows, sources = [], [], []
    for category, artifact_key, collector in _SUMMARY_CATEGORIES:
        _rows, _signals, srcs, key_traces = collector(files_found)
        sources.extend(srcs)
        page_name = __artifacts_v2__[artifact_key]["name"]
        link_cell = _detail_page_link(artifact_key)
        for finding, detail in _dedupe(key_traces):
            tsv_rows.append((category, finding, _short_text(detail), page_name))
            html_rows.append((category, finding, _short_text(detail), link_cell))

    if not tsv_rows:
        return SUMMARY_HEADERS, [], "; ".join(_dedupe(sources))
    return SUMMARY_HEADERS, (tsv_rows, html_rows), "; ".join(_dedupe(sources))


# ===========================================================================
# Notifications / export emails - retained but intentionally disabled
# ===========================================================================
# The Apple Mail export-email detection below is kept for reference and possible
# future reactivation. The artifact returns no rows on purpose.

def _parse_apple_mail(data_list, envelope_db, protected_db, source_file, compiled_email_patterns):
    if not envelope_db or not protected_db:
        return
    query = """
        SELECT
            datetime(main.messages.date_sent, 'UNIXEPOCH') AS date_sent,
            datetime(main.messages.date_received, 'UNIXEPOCH') AS date_received,
            PI.addresses.address AS address,
            PI.addresses.comment AS sender_comment,
            PI.subjects.subject AS subject,
            PI.summaries.summary AS summary,
            main.mailboxes.url AS mailbox
        FROM main.mailboxes, main.messages, PI.subjects, PI.addresses, PI.summaries
        WHERE main.messages.subject = PI.subjects.ROWID
          AND main.messages.sender = PI.addresses.ROWID
          AND main.messages.summary = PI.summaries.ROWID
          AND main.mailboxes.ROWID = main.messages.mailbox
    """
    mail_rows = get_sqlite_db_records(envelope_db, query, attach_sqlite_db_readonly(protected_db, "PI"))
    for row in mail_rows:
        combined = " ".join([
            _format_value(row["address"]), _format_value(row["sender_comment"]),
            _format_value(row["subject"]), _format_value(row["summary"]), _format_value(row["mailbox"]),
        ])
        reasons = [p for p, rx in compiled_email_patterns if rx.search(combined)]
        if not reasons:
            continue
        data_list.append((row["date_received"] or row["date_sent"] or "", "Apple Mail", row["address"],
                          _short_text(row["subject"]), _short_text(row["summary"]), "; ".join(reasons), source_file))


@artifact_processor
def notifications_surveillance(context):
    data_headers = (
        ("Timestamp", "datetime"), "Channel", "Sender or Bundle", "Subject or Title",
        "Body or Summary", "Match Reason", "Source File",
    )
    # Detection logic is retained above but intentionally disabled: this
    # artifact returns no rows.
    return data_headers, [], ""
