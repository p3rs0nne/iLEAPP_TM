
# iLEAPP — Interpersonal Surveillance edition

This repository is a fork of **iLEAPP** (iOS Logs, Events, And Plists Parser).
It adds **two artifact modules** in `scripts/artifacts/`, plus a **vendored
library** used by the unified-log artifacts:

| Path | Role |
|------|------|
| [`scripts/artifacts/Surveillance.py`](scripts/artifacts/Surveillance.py) | Generic, app-agnostic detection of interpersonal-surveillance traces. |
| [`scripts/artifacts/FamiSafe.py`](scripts/artifacts/FamiSafe.py) | Parsing of data specific to the FamiSafe monitoring app. |
| [`scripts/faul_lib/`](scripts/faul_lib/) | Vendored `forensic_aul` library — parses the Apple Unified Logs (see [Unified logs](#unified-logs-forensic_aul)). |

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

It is organised around four investigative questions read from static files, two
views derived from the Apple Unified Logs, and a summary. Each detail artifact
**only states observed data** — no interpretation, no severity, no verdict.

1. **Remote management profiles** — configuration / MDM profiles and the
   restrictions they enforce (forced encrypted backup from `Truth.plist`, VPN
   from `EffectiveUserSettings.plist`), the managed applications
   (`MDMAppManagement.plist`), the settings-change history
   (`MCSettingsEvents.plist`), and `MCState/Shared/MDM.plist`. Configuration-profile
   stubs are reported **one row per payload**, with the payload type decoded to
   plain language (Restrictions, Web content filter, Passcode policy, Wi-Fi, VPN,
   certificate, MDM enrolment, …). A remote-management profile on a personal
   device is one of the strongest indicators.
2. **Sensitive permissions** — one row per app, listing the sensitive permissions
   it holds: microphone / camera / photos / motion from `TCC.db` (decoded as in
   iLEAPP's own `tcc.py`), plus location from locationd's `clients.plist` — a file
   iLEAPP does not otherwise parse. Beyond an explicit location grant, the module
   surfaces an app's **background-location capability** and
   significant-location-change monitoring, which is how a monitoring app's reach
   usually shows up.
3. **Account associations** — a third-party account linked to the device:
   family-circle membership (`CircleCache.plist`, `familyCircleCache`,
   `JFamilyCircle.plist`, `RMAdminStore-Local.sqlite`), an account added to
   iMessage / FaceTime (`TransparencyModel.sqlite`), and location sharing
   (`idstatuscache.plist`, `Identity Lookup Service.tsv`).
4. **Pairing and backup traces** — trusted-host identifiers (SystemBUID, HostID,
   host name) from the lockdown log (`handle_pair`) and pair records, the backup
   library identifier (`com.apple.atc.plist`, `data_ark.plist`), and
   current/previous backup dates (`Info.plist`, `com.apple.ldbackup.plist`).

Two further artifacts read the **Apple Unified Logs** (parsed with the vendored
`forensic_aul` library — see [Unified logs](#unified-logs-forensic_aul)):

5. **Unified-log backup events** — **local** (computer) backup sessions: a
   connected computer running `BackupAgent2` through the `com.apple.mobilebackup2`
   service, each dated with its exact duration. iCloud backups (the device's own
   routine) are deliberately excluded.
6. **Unified-log paired-computer presence** — companion-link / Rapport discovery
   of a paired computer **by name**, over USB / Bluetooth LE / Wi-Fi, with
   timestamps. This dates when a specific computer was physically present, and
   typically brackets a local backup.

Finally, a **summary** rolls up the most important concrete traces found across
the categories — account identifiers, MDM enrolment and the apps it manages,
third-party apps with background/always location, paired computers — and links
each one (via a "Verify in" column) to the detail page that holds its full
context. It is an index, **not** an assessment: it assigns no severity and no
verdict.

### Detection is behaviour-based

The module keeps **no hard-coded list of "known" monitoring apps or vendors**
(such allow-lists go stale immediately and are a maintenance burden). The summary
flags by **behaviour** instead — any **MDM-managed** application, and any
**third-party app with background/always location** — which also catches unknown
apps. The detail tables always report every app and permission raw.

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
  reported as three artifacts: **Account and Device** (controlling account,
  FamiSafe member/device identifiers, device profile), **Install and Activity
  Window** (server-recorded dates: device record created, first data collection,
  first/last backup, subscription expiry), and **Monitoring Features** (each
  remotely-enabled capability with its active/inactive state).

The same pattern can be followed to add modules for other monitoring apps
(Life360, Qustodio, mSpy, …) without polluting the generic detector.

## Supported acquisition types

Designed and tested against the three acquisition types used in the research:

- a **local backup** (iTunes / Finder / iMazing),
- a **full file system (FFS)** extraction, and
- a **sysdiagnose** archive.

## Unified logs (`forensic_aul`)

The two unified-log artifacts (backup events, paired-computer presence) parse the
**Apple Unified Logs** with the vendored [`forensic_aul`](scripts/faul_lib/)
library, which turns the logs into a queryable SQLite database. Install it once
(editable, into the same environment as iLEAPP):

```
pip install -e scripts/faul_lib
```

If `forensic_aul` is not installed, those two artifacts simply log a notice and
yield nothing — the rest of the run is unaffected.

Notes:

- **Sources:** a **sysdiagnose** `system_logs.logarchive`, or an **FFS**'s loose
  `private/var/db/diagnostics` + `private/var/db/uuidtext` folders (passed to the
  library automatically). A local backup contains no unified logs.
- **Parsed once per run, shared:** the logs are parsed a single time into the
  report's `_unified_logs/` folder and reused by both artifacts; progress is
  printed to the terminal during the (multi-minute) parse.
- **Retention:** unified-log backup events persist only ~14 days, so the
  *absence* of an event is not proof that a backup never happened.

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
surveillance_unified_log_backups
surveillance_unified_log_companion
surveillance_summary
famisafe_cached_accounts
famisafe_account
famisafe_install_window
famisafe_monitoring_features
```

```
python ileapp.py -t fs -i <extraction> -o <output> -m my_profile.ilprofile
```

## Report examples

See [`examples/`](examples/): a rendered HTML report
([`examples/example_report_html/index.html`](examples/example_report_html/index.html))
and the TSV export of every artifact
([`examples/example_report/`](examples/example_report/)), produced from a test
device that was placed under FamiSafe monitoring.

## Handoff / full documentation

A detailed, self-contained write-up of the two modules (every artifact, the data
sources and their acquisition type, the summary logic, the test methodology
and results, the bugs fixed, and the known limitations) is in
[`docs/HANDOFF.md`](docs/HANDOFF.md).

## Sources and references

- **locationd `clients.plist` `Authorization` values** (used by the
  Sensitive Permissions artifact): the integer values (1 = Never/Off,
  2 = While Using, 4 = Always Allow/On, 5 = Allow Once, missing = Ask Next Time)
  are taken from Scott Koenig / Heather Charpentier, *"iOS Location Services and
  System Services ON or OFF?"*, The Forensic Scooter (2021-09-20):
  <https://theforensicscooter.com/2021/09/20/ios-location-services-and-system-services-on-or-off/>.
  These are **tested forensic values and are not the same as the documented
  `CLAuthorizationStatus` enum** (Apple Developer Documentation:
  <https://developer.apple.com/documentation/corelocation/clauthorizationstatus>).
- Related reading on Location/System Services state: DFIR Review,
  *"iOS Location Services and System Services are they ON or OFF"*:
  <https://dfir.pubpub.org/pub/4sv4kxyh>.

---

For all upstream iLEAPP documentation (features, install, build, contributing),
see [`README_og.md`](README_og.md).
