![iLEAPP](scripts/_elements/iLEAPP_banner.png)

# iLEAPP — Interpersonal Surveillance edition

This repository is a fork of **iLEAPP** (iOS Logs, Events, And Plists Parser).
**The only difference from upstream iLEAPP is the addition of two artifact
modules** in `scripts/artifacts/`:

| File | Role |
|------|------|
| [`scripts/artifacts/Surveillance.py`](scripts/artifacts/Surveillance.py) | Generic, app-agnostic detection of interpersonal-surveillance traces. |
| [`scripts/artifacts/FamiSafe.py`](scripts/artifacts/FamiSafe.py) | Parsing of data specific to the FamiSafe monitoring app. |

Everything else is unmodified upstream iLEAPP. The original project README is
preserved as [`README_og.md`](README_og.md) and remains the reference for
installation, dependencies, building, and contributing.

## Academic context

This work was carried out as part of a **master's thesis at the University of
Lausanne** (School of Criminal Justice / *École des sciences criminelles*),
in **digital forensic science**, on the subject of **interpersonal surveillance
on iOS** — i.e. the monitoring of one person's device by another (intimate
partner, family member), as opposed to state or corporate surveillance.

The module was developed with the assistance of **Claude Opus**.

The longer-term goal is to adapt this module into a **web platform performing
local-only analysis** (no data leaves the user's machine), so that non-technical
people can check their own device for signs of surveillance without needing
forensic expertise.

## What `Surveillance.py` looks for

It is organised around four investigative questions, plus a summary that turns
the findings into an overall assessment. Each detail artifact **only states
observed data** — interpretation lives solely in the summary.

1. **Remote management profiles** — configuration / MDM profiles and the
   restrictions they enforce (forced encrypted backup from `Truth.plist`, VPN
   from `EffectiveUserSettings.plist`), the list of managed applications
   (`MDMAppManagement.plist`), the settings-change history
   (`MCSettingsEvents.plist`), and `MCState/Shared/MDM.plist`. A remote-management
   profile on a personal device is one of the strongest indicators.
2. **Sensitive permissions** — microphone, photo-library and motion
   permissions from `TCC.db`, completed by location authorisation read from
   locationd's `clients.plist` (a file iLEAPP does not otherwise parse — a
   specific contribution of this module), which can reveal an always/background
   location authorisation.
3. **Account associations** — a third-party account linked to the device:
   family-circle membership (`CircleCache.plist`, `JFamilyCircle.plist`,
   `RMAdminStore-Local.sqlite`), an account added to iMessage
   (`TransparencyModel.sqlite`), and location sharing (`idstatuscache.plist`,
   `Identity Lookup Service.tsv`).
4. **Pairing and backup traces** — trusted-host identifiers (SystemBUID, HostID,
   host name) from the lockdown log (`handle_pair`) and pair records, the backup
   library identifier (`com.apple.atc.plist`, `data_ark.plist`), and
   current/previous backup dates (`Info.plist`, `com.apple.ldbackup.plist`).

A separate **assessment summary** aggregates the four categories into one of:

- **UNDER SURVEILLANCE** — at least one high-severity signal (e.g. an active
  MDM/remote-management profile, a known monitoring app holding a sensitive
  permission or always/background location).
- **MANUAL CHECK NECESSARY** — medium-severity signals only (e.g. a
  configuration profile, forced encrypted backup, a third-party app with always
  location, a family circle with other members, multiple paired computers,
  iMazing).
- **ALL CLEAR** — only informational signals, or none.

### Out of scope (mentioned, not parsed)

Unified-log events such as BackupAgent2 *Starting/Finished backup* lines and
`mdmd` / `profiled` profile install/remove events. These require unified-log
support that is not currently available in the iLEAPP environment.

## Why FamiSafe is a separate module

`Surveillance.py` deliberately contains **only signals that generalise across
applications** (standard Apple data stores). Data held *inside a specific app's
container*, with an app-specific structure, does not generalise and is therefore
kept out of `Surveillance.py`.

[`FamiSafe.py`](scripts/artifacts/FamiSafe.py) is the worked example of this
separation. It parses FamiSafe-specific stores:

- the application URL cache (`Library/Caches/<bundle>/Cache.db`,
  `cfurl_cache_receiver_data`), which retains the controlling (parent) account
  e-mail; and
- the application run logs (`.../RunLogs/com.wondershare.parentalcontrol*.log`),
  which record the controlling account, the FamiSafe member/device identifiers,
  the app version, the API endpoints contacted, and the monitoring capabilities
  enabled remotely.

The same pattern can be followed to add modules for other monitoring apps
(Life360, Qustodio, mSpy, …) without polluting the generic detector.

## Supported acquisition types

Designed and tested against the three acquisition types used in the research:

- a **local backup** (iTunes / Finder / iMazing),
- a **full file system (FFS)** extraction, and
- a **sysdiagnose** archive.

## Running it

```
python ileapp.py -t <fs|tar|zip|gz|itunes> -i <path_to_extraction> -o <output_folder>
```

To run only the surveillance modules, use a profile (`.ilprofile`) listing:

```
surveillance_remote_management
surveillance_sensitive_permissions
surveillance_account_associations
surveillance_pairing_backup
surveillance_summary
famisafe_cached_accounts
famisafe_run_logs
```

```
python ileapp.py -t fs -i <extraction> -o <output> -m my_profile.ilprofile
```

## Report examples

See [`examples/`](examples/) for example output (TSV exports of every artifact,
plus a rendered summary) produced from a test device that was placed under
FamiSafe monitoring.

---

For all upstream iLEAPP documentation (features, install, build, contributing),
see [`README_og.md`](README_og.md).
