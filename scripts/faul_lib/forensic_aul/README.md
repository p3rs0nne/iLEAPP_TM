# `forensic_aul` — library API

`forensic_aul` is the **installable core library** of the forensic_AUL project: it
parses Apple Unified Logs (iOS/macOS) into a normalised, queryable SQLite database
and provides the downstream analysis steps (annotation, diff, export). The CLI in
`launcher/` and the GUI in `gui/` are thin layers built on top of this package; you
can import it directly into your own application instead.

- **Importing is side-effect-free.** No logging is configured, no files are
  touched, and nothing is printed at import time. Configure your own
  `logging` handlers to see the library's diagnostics (it logs via
  `logging.getLogger("forensic_aul.…")`).
- **Runtime deps:** `lz4`, `PyYAML`. **Python:** 3.11–3.14 (tested on all four).

```bash
uv pip install -e .                 # core library only
uv pip install -e ".[acquire]"      # + USB device acquisition (pymobiledevice3)
```

```python
import forensic_aul
forensic_aul.__version__     # e.g. "0.1.0"
```

---

## What is exposed

Everything in the table below is re-exported at the top level
(`from forensic_aul import …`) and listed in `forensic_aul.__all__`. These are the
**only** names you should depend on; everything else under `forensic_aul.*` is an
internal implementation detail and may change.

| Name | Kind | Signature → returns | Does |
|---|---|---|---|
| `run_extract` | func | `(logarchive: Path \| Mapping[str, Path], db_path: Path, *, case_number=None, imei=None, exhibit_number=None, analyst_name=None, notes=None, batch_size=10000, work_dir=None, fast_fts=False, fast_write=False, fts=True, keep_raw=False, jobs=1, overwrite=False, progress=None)` → `ExtractResult` | Full pipeline: source → SQLite. `logarchive` is either a single path — a `.logarchive` dir, a sysdiagnose `.tar.gz`, or an FFS `.zip` (auto-detected by magic bytes, not extension) — **or** a mapping of two already-uncompressed folders `{"diagnostics": dir, "uuidtext": dir}` (see `prepare_loose_dirs`). **Refuses to write into an existing `db_path` unless `overwrite=True`** (raises `FileExistsError`). Performance/output toggles: `fts` builds the FTS5 full-text index (on by default), `fast_fts` defers its rebuild to the end, `fast_write` sets `synchronous=OFF` (faster, less crash-durable), `keep_raw` stores the raw firehose item data as JSON for traceability (off by default to save space). Returns an `ExtractResult`. |
| `run_diff` | func | `(baseline_db: Path, action_db: Path, csv_out: Path, sqlite_out: Path)` → `DiffResult` | Attributes log lines to a user action by diffing a post-action DB against a baseline. Writes a CSV (retained lines) + a SQLite DB (all post-cutoff rows with an `excluded` flag). Returns a `DiffResult`. |
| `run_export` | func | `(database: Path, output: Path, filters: ExportFilters \| None = None)` → `ExportResult` | Filtered export of an analysis DB to CSV / JSON / JSONL (format inferred from the suffix or `filters.fmt`). Knowledge-base aware. Returns an `ExportResult`. Raises `FileNotFoundError` / `ValueError` on bad input. |
| `acquire` | func | `(case_number: str, *, output_dir=Path("."), udid=None, start_time=None, size_limit=None, age_limit=None, exhibit=None, analyst=None, notes=None, extract=False, db_path=None, batch_size=1000, confirm=None)` → `AcquireResult` | **Collect a `.logarchive` from a USB-connected iOS device** (needs the optional `pymobiledevice3` — `pip install "forensic-aul[acquire]"`). Hashes it, writes a `.acquisition.json` report, optionally runs `run_extract`. `confirm(device)->bool` is an optional pre-collection hook (the library does no I/O itself). Raises `ImportError` (dep missing), `AcquisitionAborted`, `AcquisitionError`. |
| `AcquisitionError` / `AcquisitionAborted` | exceptions | — | Raised by `acquire`: a failure, or the `confirm` hook declining. |
| `DeviceInfo` | dataclass | device metadata (`udid`, `imei`, `serial_number`, SIMs, …) | The connected-device record; passed to the `confirm` hook and on `AcquireResult.device`. |
| `ExportFilters` | dataclass | fields: `fmt, time_from, time_to, last, process, subsystem, level, grep, signature, action, tag, annotated_only, include_fields` | Declarative filter/option set for `run_export` (decoupled from any CLI). |
| `load_kb` | func | `(root: Path \| str)` → `KnowledgeBase` | Load + validate the YAML knowledge base (the signature definitions). Raises `KnowledgeBaseError` on invalid content. |
| `annotate_database` | func | `(db: Path \| str, kb: KnowledgeBase, *, only_ids=None, only_tags=None)` → `AnnotateResult` | Open the analysis DB at `db`, match every selected signature against `logs`, write `kb_signatures` / `log_annotations`, commit and close. Use this to (re-)annotate **at will** without re-extracting. Returns an `AnnotateResult` (`.counts` is the `signature_id → match_count` mapping). Raises `FileNotFoundError`. |
| `annotate_connection` | func | `(conn: sqlite3.Connection, kb: KnowledgeBase, *, only_ids=None, only_tags=None)` → `AnnotateResult` | Same as `annotate_database` but on a caller-owned connection (for in-memory DBs / caller-managed transactions); `result.db_path` is `None`. |
| `KnowledgeBaseError` | exception | — | Raised by `load_kb` for malformed/invalid knowledge bases. |
| `prepare_source` | func | `(source: Path \| Mapping[str, Path], *, work_dir: Path \| None = None)` → `PreparedSource` | Normalise any supported acquisition to a logarchive layout, capturing the content SHA-256, an archive fingerprint, and the iOS version when available. A single path is auto-detected (logarchive / sysdiagnose / FFS); a mapping `{"diagnostics": dir, "uuidtext": dir}` is routed to `prepare_loose_dirs`. |
| `prepare_loose_dirs` | func | `(diagnostics: Path, uuidtext: Path, *, work_dir: Path \| None = None)` → `PreparedSource` | Normalise **two already-uncompressed folders** — the on-device `private/var/db/diagnostics/` (tracev3 material) and `private/var/db/uuidtext/` (format-string tables), i.e. the same pair an FFS zip carries but loose on disk — into one logarchive root. Merged by **hard link** (zero-copy), originals only read. Hard links need the work dir on the same filesystem and aren't supported on a few (exFAT, some network drives); when one can't be made the file is **copied** instead (identical result, extra disk, logs a `WARNING`). `archive_fingerprint` is `None` (no single archive); content/per-file hashes are still computed. Raises `ValueError` if either path is not a directory or together they hold no files. |
| `PreparedSource` | dataclass | fields incl. `source_type, original_path, logarchive_root, content_sha256, file_hashes, archive_fingerprint, ios_product_version`; methods `verify_unchanged()`, `cleanup()` | The result of `prepare_source` / `prepare_loose_dirs` (a temporary extraction is auto-cleaned via `cleanup()`). |
| `SourceType` | enum | `LOGARCHIVE`, `SYSDIAGNOSE`, `FILESYSTEM`, `LOOSE_DIRS` | Discriminates the acquisition type (`LOOSE_DIRS` = the two-folder mapping). |
| `compute_sha256` | func | `(path: Path \| str)` → `str` | SHA-256 of a single file (chain of custody). |
| `hash_logarchive` | func | `(logarchive: Path \| str)` → `tuple[str, dict[str, str]]` | `(content_digest, {relative_path: sha256})` over a logarchive tree (sorted walk). |
| `init_schema` | func | `(conn: sqlite3.Connection, enable_fts5=True, *, defer_fts_triggers=False, create_indexes=True)` → `bool` | Create all tables/indexes (and FTS5 if available). Returns whether FTS5 was created. |
| `apply_pragmas` | func | `(conn: sqlite3.Connection, *, synchronous="NORMAL", sort_threads=0)` → `None` | Apply the bulk-insertion pragmas (WAL, durability, sort threads). Call before writing. |
| `assign_ordering` | func | `(conn: sqlite3.Connection, boot_rank_by_uuid: dict[str, int])` → `None` | Assign the deterministic `source_order` + `event_order` columns after a load. |
| `LogEntry` | dataclass | the canonical log-row model | Useful for type hints and post-processing of parsed rows. |
| `ExtractResult` | dataclass | `db_path, metadata_id, entry_count, parse_errors, source_type, source_sha256, device_model, ios_build, ios_version, boot_uuid, time_range, source_files_verified, source_files_changed, source_files_unverifiable` | Returned by `run_extract` — the output path plus the run facts (incl. the per-file integrity re-check counts), so you can chain (e.g. `annotate_database(res.db_path, kb)`) without re-querying. |
| `DiffResult` | dataclass | `csv_path, sqlite_path, retained, excluded` | Returned by `run_diff`. |
| `ExportResult` | dataclass | `output_path, rows, fmt` | Returned by `run_export`. |
| `AnnotateResult` | dataclass | `counts, total_matches, signatures_run, signatures_matched, db_path` | Returned by `annotate_database` / `annotate_connection`. `.counts` is the `signature_id → match_count` mapping. |
| `AcquireResult` | dataclass | `logarchive_path, logarchive_sha256, file_count, device, report_path, extract_result` | Returned by `acquire`. `extract_result` is set only when `acquire(extract=True)`. |

> Note: `annotate_database` is **path-based** (like `run_extract` / `run_diff` /
> `run_export`), so you can re-annotate a saved database at any time. Reach for
> `annotate_connection` only when you already hold a connection (e.g. an in-memory
> database or a caller-managed transaction).

---

## Quick start

```python
import logging
from pathlib import Path
from forensic_aul import (
    run_extract, prepare_source, load_kb, annotate_database, run_export, ExportFilters,
)

logging.basicConfig(level=logging.INFO)   # the library logs; the host app configures handlers

# 1) Parse an acquisition (logarchive dir / sysdiagnose .tar.gz / FFS .zip) → SQLite.
#    run_extract prepares the source itself, but you can inspect it first:
source = prepare_source(Path("acquisition.tar.gz"))
print(source.source_type, source.content_sha256)

res = run_extract(
    source.logarchive_root, Path("case.db"),
    case_number="CASE-2024-001", imei="35…",
    jobs=8,            # parser process budget; result is identical for any value.
                       # run_extract itself defaults to jobs=1; the CLI/GUI resolve a
                       # memory-aware default via engine.utils.system.resolve_auto_jobs.
    overwrite=True,    # replace case.db if it already exists (else FileExistsError)
)
source.cleanup()       # remove the temporary extraction (no-op for a plain dir)
print(res.entry_count, res.ios_version, res.time_range)

# 2) (Optional) Annotate against a YAML knowledge base of action signatures.
#    Path-based + chainable: reuse res.db_path, re-run any time the KB improves.
kb = load_kb(Path("knowledge_base/"))     # the KB data directory (VERSION + signatures/)
ann = annotate_database(res.db_path, kb)
print(ann.total_matches, ann.counts)      # ann.counts → {signature_id: match_count}

# 3) Export a filtered, annotation-aware view.
out = run_export(
    res.db_path, Path("report.csv"),
    ExportFilters(level=["Error", "Fault"], annotated_only=True),
)
print(f"exported {out.rows} rows → {out.output_path}")
```

You can also use `prepare_source` as a context manager so its temporary
extraction is always cleaned up:

```python
with prepare_source(Path("acquisition.zip")) as src:
    run_extract(src.logarchive_root, Path("case.db"), case_number="C1")
```

If the two unified-log folders are already uncompressed on disk (the on-device
`private/var/db/diagnostics/` and `private/var/db/uuidtext/`), pass them as a
mapping instead of an archive — they are merged into a logarchive root by hard
link (zero-copy, originals untouched):

```python
run_extract(
    {"diagnostics": Path("dump/diagnostics"), "uuidtext": Path("dump/uuidtext")},
    Path("case.db"), case_number="C1",
)
# or prepare explicitly:
with prepare_loose_dirs(Path("dump/diagnostics"), Path("dump/uuidtext")) as src:
    run_extract(src.logarchive_root, Path("case.db"), case_number="C1")
```

The package ships a `py.typed` marker, so type-checkers (mypy, pyright) and IDEs
pick up its annotations when you depend on it.

### Acquiring from a device (optional)

With the `acquire` extra installed, collect straight from a USB-connected iOS
device and chain into the rest of the pipeline:

```python
from forensic_aul import acquire

res = acquire("CASE-2024-001", output_dir=Path("evidence"), extract=True)
print(res.logarchive_path, res.logarchive_sha256, res.device.imei)
print(res.extract_result.entry_count)     # because extract=True
```

`acquire` performs no console I/O — pass `confirm=lambda device: ...` to show a
summary / prompt before collection. It raises `ImportError` if `pymobiledevice3`
is not installed.

---

## Internal layout (not part of the stable API)

The package is split into two layers that make the architecture self-documenting:
**`engine/`** is the pure backend (no notion of a command, no prompting, no
presentation), and **`ops/`** holds the callable operations. Each operation
follows a uniform shape — a main module plus helpers, and a `report.py` of pure
`format_*(outcome) -> str` functions a caller renders *at will* (operations
never print or build a report themselves).

### `engine/` — pure backend

| Sub-package | Responsibility |
|---|---|
| `engine/parser/` | low-level tracev3 / firehose / catalog / timesync / dsc / uuidtext decoding; plus `string_cache` (UUIDText+DSC cache) and `format_string` (format-string resolution) |
| `engine/database/` | SQLite schema, batched writer (+ `register_source_file`), post-load ordering |
| `engine/models/` | data structures, split by domain: `chunks`, `firehose`, `strings`, `timesync`, `log_entry` (all re-exported from `engine.models`) |
| `engine/integrity.py` | forensic hashing (`compute_sha256`, `hash_logarchive`) and operational-log sealing / source-file re-verification |
| `engine/ios_builds.py` | build-code → iOS-version lookup (reference data) |
| `engine/utils/` | logging helpers, time conversion, the reusable progress reporter, host probes (`system.py`: physical-core / RAM-aware `--jobs` default) |

### `ops/` — callable operations

| Sub-package | Responsibility |
|---|---|
| `ops/extraction/` | the extract pipeline (`extract.py`), the `shutdown.log` sidecar parser, and input-source detection & preparation (`source.py`) |
| `ops/acquisition/` | device acquisition (`acquire`) + device metadata + the `.acquisition.json` report writer |
| `ops/annotation/` | apply a knowledge base to a DB (`matcher`) |
| `ops/knowledge_base/` | load / lint / model the YAML KB (the KB *data* lives in the repo-root `knowledge_base/`) |
| `ops/identify/` | baseline-vs-action diff (`run_diff`) |
| `ops/export/` | filtered CSV/JSON/JSONL export (`run_export`) |
| `ops/summary/` | read-only summary of an analysis DB |
| `ops/verify/` | chain-of-custody re-verification |

### Top-level

| Module | Responsibility |
|---|---|
| `config.py` | tuneable constants/defaults |
| `outcomes.py` | the operation result dataclasses (`ExtractResult`, `DiffResult`, …) |
| `testing/` | **runtime** validation tooling (device capture + `log show` reference + comparator + the `test` pipeline) used by the `faul test` command — *not* the project's pytest suite (that lives in the repo-root `tests/`) |

Prefer the top-level re-exports; importing from these sub-modules ties you to
internal paths that may move between versions.
