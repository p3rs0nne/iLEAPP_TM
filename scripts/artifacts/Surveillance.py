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
    -  Assessment summary           (surveillance_summary)

The four detail artifacts only state observed data; no interpretation is added
to their tables. Interpretation lives exclusively in the summary, which derives
an overall assessment (under surveillance / manual check necessary / all clear)
from signals raised while collecting each category.

Designed to run against the three acquisition types used in the underlying
research: a local (iTunes/Finder/iMazing) backup, a full file system (FFS)
extraction, and a sysdiagnose archive.

Only data that generalises across applications (standard Apple stores) is
collected here. Data held inside a specific monitoring app's container, with an
app-specific structure, is handled by dedicated modules such as FamiSafe.py.

Out of scope (mentioned for completeness, not parsed here): unified-log events
such as BackupAgent2 "Starting/Finished backup" lines and mdmd / profiled
profile install/remove events.

Developed as part of a master's thesis at the University of Lausanne (School of
Criminal Justice, digital forensic science), with the assistance of Claude Opus.
"""

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
        "notes": "Out of scope: BackupAgent2 start/finish unified-log events.",
        "paths": (
            "*/MobileLockdown/lockdownd.log",                      # sysdiagnose
            "*/MobileLockdown/lockdownd.log.1",                    # sysdiagnose
            "*/logs/lockdownd.log",                               # sysdiagnose
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
    # "surveillance_summary": {
    #     "name": "Surveillance - Assessment Summary",
    #     "description": (
    #         "Aggregated assessment derived from the four surveillance detail "
    #         "artifacts. Reports an overall status (under surveillance / manual "
    #         "check necessary / all clear) together with the indicators that led "
    #         "to it."
    #     ),
    #     "author": "Julie / University of Lausanne (with Claude Opus)",
    #     "creation_date": "2026-06-14",
    #     "last_update_date": "2026-06-14",
    #     "requirements": "none",
    #     "category": "Surveillance",
    #     "notes": "The assessment criteria are documented in this module's source.",
    #     # Union of the four categories' paths (see each category above for the
    #     # source type - FFS / backup / sysdiagnose - of every file).
    #     "paths": (
    #         "*/UserConfigurationProfiles/PublicInfo/Truth.plist",
    #         "*/UserConfigurationProfiles/EffectiveUserSettings.plist",
    #         "*/ConfigurationProfiles/MDMAppManagement.plist",
    #         "*/ConfigurationProfiles/MCSettingsEvents.plist",
    #         "*/ConfigurationProfiles/ProfileTruth.plist",
    #         "*/ConfigurationProfiles/*.stub",
    #         "*/MCState/Shared/MDM.plist",
    #         "*/MCState/Shared/PayloadDependency.plist",
    #         "*/MCState/Shared/*.stub",
    #         "*/mobile/Library/TCC/TCC.db*",
    #         "*/Accessibility/TCC.db*",
    #         "*/Caches/locationd/clients.plist",
    #         "*/Caches/FamilyCircle/CircleCache.plist",
    #         "*/CircleCache.plist",
    #         "*/JFamilyCircle.plist",
    #         "*/com.apple.remotemanagementd/RMAdminStore-Local.sqlite*",
    #         "*/com.apple.transparencyd/TransparencyModel.sqlite*",
    #         "*/IdentityServices/idstatuscache.plist",
    #         "*/MobileLockdown/lockdownd.log",
    #         "*/MobileLockdown/lockdownd.log.1",
    #         "*/logs/lockdownd.log",
    #         "*/Lockdown/pair_records/*.plist",
    #         "*/Library/Preferences/com.apple.atc.plist",
    #         "*/Library/Preferences/com.apple.ldbackup.plist",
    #         "*/root/Library/Lockdown/data_ark.plist",
    #         "info.plist",
    #     ),
    #     "output_types": ["html", "tsv"],
    #     "artifact_icon": "alert-triangle",
    # },
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

# Bundle identifiers of commonly encountered monitoring / "parental control" /
# stalkerware applications.
SURVEILLANCE_APPS = {
    "com.life360.safetymapb": "Life360",
    "com.life360.safetymap": "Life360",
    "com.tencentmobile.famisafe": "FamiSafe",
    "com.wondershare.parentalcontrol": "Wondershare FamiSafe",
    "com.wondershare.parentalcontrolkid": "Wondershare FamiSafe (Kid)",
    "com.qustodio.family": "Qustodio",
    "com.mspy.mspy": "mSpy",
    "com.flexispy.flexispy": "FlexiSPY",
    "com.spyic.spyic": "Spyic",
    "com.hoverwatch.hoverwatch": "Hoverwatch",
    "com.cocospy.cocospy": "Cocospy",
    "com.eyezy.eyezy": "Eyezy",
}

# Substrings used to recognise a known monitoring vendor inside an MDM profile.
SURVEILLANCE_MDM_MARKERS = (
    "famisafe", "wondershare", "qustodio", "mspy", "flexispy", "spyic",
    "hoverwatch", "cocospy", "eyezy", "mobicip", "bark", "netnanny",
    "kidslox", "ourpact",
)

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

REMOTE_MANAGEMENT_HEADERS = ("Indicator", "Field", "Value", "Source File")

_RM_PLISTS = {
    "mdm.plist", "mdmappmanagement.plist", "truth.plist", "profiletruth.plist",
    "effectiveusersettings.plist", "publiceffectiveusersettings.plist",
    "mcsettingsevents.plist", "payloaddependency.plist",
}


def _collect_remote_management(files_found):
    """Return (rows, signals, sources) for the remote-management category."""
    rows, signals, sources = [], [], []
    has_mdm = mdm_vendor = ""
    profile_count = 0
    force_encrypted_backup = vpn_indicator = False

    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()

        if name.endswith(".stub"):
            profile_count += 1
            sources.append(file_found)
            rows.append(("Configuration profile present", "profile stub", Path(file_found).name, file_found))
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
                    rows.append(("MDM enrollment", field, _short_text(data[field]), file_found))
            blob = json.dumps(data, default=str).lower()
            for marker in SURVEILLANCE_MDM_MARKERS:
                if marker in blob:
                    mdm_vendor = marker
                    break

        elif name == "mdmappmanagement.plist":
            managed = data.get("metadataByBundleID", {})
            if isinstance(managed, dict):
                for bundle_id, _meta in managed.items():
                    label = SURVEILLANCE_APPS.get(bundle_id, "")
                    value = bundle_id + (f" ({label})" if label else "")
                    rows.append(("Managed application", "bundle id", value, file_found))
                    if label:
                        signals.append((SEV_HIGH, "Known monitoring app is MDM-managed", value))

        elif name in ("truth.plist", "profiletruth.plist"):
            for _kp, key, value in _iter_plist_values(data, {"forceEncryptedBackup"}):
                pref = value.get("preference") if isinstance(value, dict) else value
                rows.append(("Restriction (Truth.plist)", key, _format_value(pref), file_found))
                if pref is True or str(pref).lower() in ("1", "true", "yes"):
                    force_encrypted_backup = True

        elif name in ("effectiveusersettings.plist", "publiceffectiveusersettings.plist"):
            for _kp, key, value in _iter_plist_values(data, {"vpn"}):
                inner = value.get("value", value.get("preference", value)) if isinstance(value, dict) else value
                rows.append(("Restriction (EffectiveUserSettings)", key, _format_value(inner), file_found))
                vpn_indicator = True

        elif name == "mcsettingsevents.plist":
            for setting, kind, event, process, ts in _iter_settings_events(data):
                rows.append(("Settings change", setting, f"{event} {kind} by {process} @ {ts}", file_found))

        elif name == "payloaddependency.plist":
            for kp, key, value in _iter_plist_values(data, {"PayloadIdentifier", "Payload"}):
                rows.append(("Profile payload dependency", key, _short_text(value), file_found))

    if has_mdm:
        evidence = "MDM profile present" + (f" - vendor marker '{mdm_vendor}'" if mdm_vendor else "")
        signals.append((SEV_HIGH, "Remote management (MDM) enrolled on device", evidence))
    if profile_count:
        signals.append((SEV_MEDIUM, "Configuration profile(s) installed", f"{profile_count} profile stub(s)"))
    if force_encrypted_backup:
        signals.append((SEV_MEDIUM, "Encrypted backup forced by profile", "Truth.plist forceEncryptedBackup"))
    if vpn_indicator:
        signals.append((SEV_MEDIUM, "VPN governed by configuration profile", "EffectiveUserSettings.plist"))
    return rows, signals, _dedupe(sources)


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
    rows, _signals, sources = _collect_remote_management(files_found)
    return REMOTE_MANAGEMENT_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Category 2 - Sensitive permissions
# ===========================================================================

SENSITIVE_PERMISSIONS_HEADERS = (
    ("Last Modified", "datetime"), "App / Client", "Bundle ID", "Permission",
    "Authorisation", "Source File",
)


def _tcc_access_label(raw_value, has_auth_value):
    if raw_value is None:
        return ""
    if has_auth_value:
        return {0: "Not allowed", 1: "Unknown / prompt", 2: "Allowed",
                3: "Limited / always (service-dependent)"}.get(raw_value, str(raw_value))
    return {0: "Not allowed", 1: "Allowed"}.get(raw_value, str(raw_value))


def _read_tcc(file_found, rows, signals):
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
        allowed = (has_auth_value and raw_access in (2, 3)) or ((not has_auth_value) and raw_access == 1)
        last_modified = _unix_ts(record["last_modified"]) if has_last_modified else ""
        label = SURVEILLANCE_APPS.get(client, "")
        rows.append((
            last_modified, label or client, client,
            service.replace("kTCCService", "") + f" ({SENSITIVE_TCC_SERVICES.get(service, '')})",
            _tcc_access_label(raw_access, has_auth_value), file_found,
        ))
        if allowed and client in SURVEILLANCE_APPS:
            signals.append((SEV_HIGH, "Monitoring app granted a sensitive permission",
                            f"{label} ({client}) -> {service.replace('kTCCService', '')}"))


def _read_locationd_clients(file_found, rows, signals):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    for client_key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        authorization = entry.get("Authorization")
        mask = entry.get("SupportedAuthorizationMask")
        in_use = entry.get("InUseLevel")
        if authorization is None and mask is None and in_use is None:
            continue
        bundle_id = entry.get("BundleId", "")
        identifier = bundle_id or str(client_key)
        details = []
        if authorization is not None:
            details.append(f"status={LOCATION_AUTH_STATUS.get(authorization, _format_value(authorization))}")
        if mask is not None:
            details.append(f"mask={mask}")
        if in_use is not None:
            details.append(f"inUseLevel={in_use}")
        rows.append(("", SURVEILLANCE_APPS.get(bundle_id, identifier), bundle_id,
                     "Location (clients.plist)", ", ".join(details), file_found))
        # Authorization == 4 means "Always Allow" for an application (see source
        # cited at LOCATION_AUTH_STATUS).
        if authorization == 4:
            label = SURVEILLANCE_APPS.get(bundle_id, "")
            if label:
                signals.append((SEV_HIGH, "Monitoring app has always-allow location", f"{label} ({bundle_id})"))
            elif bundle_id and not bundle_id.startswith("com.apple"):
                signals.append((SEV_MEDIUM, "Third-party app has always-allow location", bundle_id))


def _collect_sensitive_permissions(files_found):
    rows, signals, sources = [], [], []
    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        if name == "tcc.db":
            sources.append(file_found)
            _read_tcc(file_found, rows, signals)
        elif name == "clients.plist":
            sources.append(file_found)
            _read_locationd_clients(file_found, rows, signals)
    return rows, signals, _dedupe(sources)


@artifact_processor
def surveillance_sensitive_permissions(context):
    files_found = context.get_files_found()
    rows, _signals, sources = _collect_sensitive_permissions(files_found)
    return SENSITIVE_PERMISSIONS_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Category 3 - Account associations
# ===========================================================================

ACCOUNT_ASSOCIATION_HEADERS = (
    "Record Type", "Identity / Account", "Detail", "Context", "Source File",
)


def _read_circlecache(file_found, rows, signals):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    circle = data.get("circle", {})
    members = circle.get("family-members", []) if isinstance(circle, dict) else []
    others = 0
    for member in members:
        if not isinstance(member, dict):
            continue
        apple_id = member.get("member-apple-id", "")
        is_me = member.get("is-me", False)
        role = []
        if is_me:
            role.append("device owner")
        if member.get("member-is-organizer"):
            role.append("organizer")
        if member.get("member-is-parent-account"):
            role.append("parent")
        detail = [f"name={member.get('member-first-name', '')} {member.get('member-last-name', '')}".strip()]
        if member.get("member-phone-numbers"):
            detail.append(f"phone={member.get('member-phone-numbers')}")
        if member.get("member-join-date-epoch"):
            detail.append(f"joined={_unix_ts(member.get('member-join-date-epoch'))}")
        rows.append(("Family circle member", apple_id, "; ".join(p for p in detail if p),
                     ", ".join(role) if role else "member", file_found))
        if not is_me:
            others += 1
            if member.get("member-is-organizer") or member.get("member-is-parent-account"):
                signals.append((SEV_MEDIUM, "Family circle controlled by another account",
                                f"{apple_id} ({', '.join(role)})"))
    if others:
        signals.append((SEV_MEDIUM, "Device belongs to a family circle with other members",
                        f"{others} other member(s)"))


def _read_jfamilycircle(file_found, rows, signals):
    data = get_plist_file_content(file_found)
    if not isinstance(data, dict):
        return
    members = (((data.get("circle") or {}).get("family") or {}).get("members")) or []
    for member in members:
        if not isinstance(member, dict):
            continue
        rows.append(("Family circle member (JFamilyCircle)", member.get("accountName", ""),
                     f"name={member.get('firstName', '')} {member.get('lastName', '')}".strip(),
                     f"dsid={member.get('ICloudDsid', '')}", file_found))


def _read_rm_admin_store(file_found, rows, signals):
    selected, db_rows = _fetch_existing_columns(
        file_found, "ZCOREUSER",
        ["ZAPPLEID", "ZDSID", "ZALTDSID", "ZISFAMILYORGANIZER", "ZISPARENT",
         "ZFAMILYMEMBERTYPE", "ZGIVENNAME", "ZFAMILYNAME"])
    for row in db_rows:
        details = {c: _format_value(row[c]) for c in selected}
        rows.append(("RemoteManagement family user", details.get("ZAPPLEID", ""),
                     json.dumps(details, ensure_ascii=False), "ZCOREUSER", file_found))


def _read_transparency_model(file_found, rows, signals):
    selected, db_rows = _fetch_existing_columns(
        file_found, "ZPEERSTATE", ["ZAPPLICATION", "ZURI", "ZOPTEDIN", "ZSEENDATE", "ZEVEROPTEDIN"])
    for row in db_rows:
        uri = _format_value(row["ZURI"]) if "ZURI" in selected else ""
        if not uri:
            continue
        seen = _coredata_ts(row["ZSEENDATE"]) if "ZSEENDATE" in selected and row["ZSEENDATE"] else ""
        application = _format_value(row["ZAPPLICATION"]) if "ZAPPLICATION" in selected else ""
        rows.append(("iMessage/FaceTime key-transparency peer", uri,
                     f"application={application}; seen={seen}", "ZPEERSTATE", file_found))


def _read_idstatuscache(file_found, rows, signals):
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
    for service, entries in data.items():
        if not isinstance(entries, dict) or not entries:
            continue
        label = labels.get(service, service)
        for identity, status in entries.items():
            lookup = _coredata_ts(status.get("LookupDate")) if isinstance(status, dict) else ""
            rows.append(("Identity status cache", identity, f"service={label}; lookup={lookup}",
                         service, file_found))
            if service in ("com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd"):
                signals.append((SEV_MEDIUM, "Location-sharing identity present", f"{identity} via {label}"))


def _read_identity_lookup_tsv(file_found, rows, signals):
    for number, line in enumerate(_read_text_lines(file_found), start=1):
        if number == 1 and "Partner" in line:
            continue
        if any(t in line.lower() for t in ("imessage", "facetime", "icloud", "x-apple", "mailto")):
            rows.append(("Identity Lookup Service (TSV export)", "", _short_text(line),
                         f"line {number}", file_found))


def _collect_account_associations(files_found):
    rows, signals, sources = [], [], []
    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        reader = {
            "circlecache.plist": _read_circlecache,
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
        reader(file_found, rows, signals)
    return rows, signals, _dedupe(sources)


@artifact_processor
def surveillance_account_associations(context):
    files_found = context.get_files_found()
    rows, _signals, sources = _collect_account_associations(files_found)
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
    field_re = re.compile(r'^\s*(?P<key>HostName|SystemBUID|HostID)\s*=\s*"?(?P<val>[^";]+)"?')
    set_re = re.compile(
        r"handle_set_value:\s*(?P<actor>.+?)\s+attempting to set "
        r"\[(?P<domain>[^\]]*)\]:\[(?P<key>[^\]]+)\]\s+to\s+\[(?P<value>[^\]]*)\]", re.IGNORECASE)
    interesting_set_keys = {"LastBackupComputerName", "LastBackupComputerType",
                            "LastiTunesBackupDate", "HostName", "SystemBUID"}
    seen_pair = set()
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
        detail = "; ".join(f"{k}={block[k]}" for k in ("HostName", "SystemBUID", "HostID") if k in block)
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
    rows, signals, sources = [], [], []
    host_names = set()
    pair_record_count = 0
    imazing_seen = False

    for file_found in _dedupe(files_found):
        name = Path(file_found).name.lower()
        path_norm = str(file_found).replace("\\", "/")

        if name in ("lockdownd.log", "lockdownd.log.1"):
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
                sources.append(file_found)
                for key, value in data.items():
                    rows.append(("Backup preference", key, _format_value(value), "MobileBackup", file_found))

    host_names = {h for h in host_names if h}
    if host_names:
        signals.append((SEV_MEDIUM if len(host_names) > 1 else SEV_INFO,
                        "Device paired with computer(s)", "trusted host(s): " + ", ".join(sorted(host_names))))
    if imazing_seen:
        signals.append((SEV_MEDIUM, "Third-party backup tool (iMazing) paired", "lockdownd.log handle_pair"))
    if pair_record_count:
        signals.append((SEV_MEDIUM if pair_record_count > 1 else SEV_INFO,
                        "Pairing record(s) present", f"{pair_record_count} pair record(s)"))
    return rows, signals, _dedupe(sources)


@artifact_processor
def surveillance_pairing_backup(context):
    files_found = context.get_files_found()
    rows, _signals, sources = _collect_pairing_backup(files_found)
    return PAIRING_BACKUP_HEADERS, _dedupe_rows(rows), "; ".join(sources)


# ===========================================================================
# Assessment summary
# ===========================================================================

SUMMARY_HEADERS = ("Category", "Status", "Indicator", "Evidence")

_SUMMARY_CATEGORIES = (
    ("1. Remote management profiles", _collect_remote_management),
    ("2. Sensitive permissions", _collect_sensitive_permissions),
    ("3. Account associations", _collect_account_associations),
    ("4. Pairing and backup traces", _collect_pairing_backup),
)


def _status_for_severity(severity):
    if severity >= SEV_HIGH:
        return "UNDER SURVEILLANCE"
    if severity >= SEV_MEDIUM:
        return "MANUAL CHECK NECESSARY"
    return "ALL CLEAR"


@artifact_processor
def surveillance_summary(context):
    """Aggregate the four categories into an overall surveillance assessment.

    Assessment criteria:
      - UNDER SURVEILLANCE     : at least one HIGH-severity signal (e.g. an
                                 active MDM/remote-management profile, a known
                                 monitoring app holding a sensitive permission or
                                 always/background location).
      - MANUAL CHECK NECESSARY : no HIGH signal but at least one MEDIUM signal
                                 (e.g. a configuration profile, forced encrypted
                                 backup, a third-party app with always location,
                                 a family circle with other members, multiple
                                 paired computers, iMazing).
      - ALL CLEAR              : only informational signals, or none.
    """
    files_found = context.get_files_found()
    rows = []
    overall_severity = 0
    per_category = []

    for label, collector in _SUMMARY_CATEGORIES:
        _data, signals, _sources = collector(files_found)
        max_sev = max((s[0] for s in signals), default=0)
        overall_severity = max(overall_severity, max_sev)
        per_category.append((label, signals, max_sev))

    overall_status = _status_for_severity(overall_severity)
    rows.append(("OVERALL ASSESSMENT", overall_status,
                 "Aggregated across the four categories below",
                 "See category rows and the detail artifacts for the underlying data."))

    for label, signals, max_sev in per_category:
        if signals:
            for severity, indicator, evidence in sorted(signals, key=lambda s: -s[0]):
                rows.append((label, _status_for_severity(severity), indicator, evidence))
        else:
            rows.append((label, _status_for_severity(max_sev), "No surveillance indicator detected", ""))

    logfunc(f"Surveillance assessment: {overall_status}")
    return SUMMARY_HEADERS, rows, "Derived from the four surveillance detail artifacts"


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
