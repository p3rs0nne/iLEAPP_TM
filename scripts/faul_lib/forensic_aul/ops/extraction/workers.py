"""Worker-process parsing for multiprocessing (ProcessPoolExecutor) path.

Defines : _WORKER, _worker_init, _worker_parse
Used by : forensic_aul.ops.extraction.extract (_run_parse, parallel path)
Uses    : forensic_aul.ops.extraction.tracev3_parse (_process_tracev3),
          forensic_aul.ops.extraction.oversize_pass (OversizeCache),
          forensic_aul.engine.models (TimesyncBoot, LogEntry),
          forensic_aul.engine.parser.string_cache (StringCacheProvider)

Pickling note
-------------
ProcessPoolExecutor pickles *_worker_init* and *_worker_parse* by their
**qualified name** — both must remain module-level in this file and must not be
nested inside another function or turned into closures.  The extract pipeline
references them as ``workers._worker_init`` / ``workers._worker_parse`` (or via
a direct import that resolves to the same qualified name).

Worker processes parse tracev3 files in parallel and return resolved LogEntry
batches to the single writer (the main process). All DB ids a row needs are
resolved from maps prepared in the main process, so a worker never opens the
database. The read-only string cache is loaded from disk in each worker
(cross-platform: works under spawn and fork) rather than pickled across.
"""

from __future__ import annotations

from pathlib import Path

from forensic_aul.engine.models import LogEntry, TimesyncBoot
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.ops.extraction.oversize_pass import OversizeCache
from forensic_aul.ops.extraction.tracev3_parse import _process_tracev3

# ── Worker-process parsing (multiprocessing) ──────────────────────────────────

_WORKER: dict[str, object] = {}


def _worker_init(
    logarchive_root: Path,
    timesync_data: dict[str, TimesyncBoot],
    oversize_cache: OversizeCache,
    boot_uuid_to_timesync_file_id: dict[str, int],
    anchor_id_map: dict[tuple[int, int], int],
    tracev3_file_ids: dict[str, int],
    uuid_file_ids: dict[str, int],
    keep_raw: bool,
) -> None:
    """Initialise one worker: load the read-only string cache from disk once."""
    strings = StringCacheProvider(logarchive_root)
    strings.load_content()
    strings.set_uuid_file_ids(uuid_file_ids)
    _WORKER.clear()
    _WORKER.update(
        root=logarchive_root,
        strings=strings,
        timesync_data=timesync_data,
        oversize_cache=oversize_cache,
        boot_map=boot_uuid_to_timesync_file_id,
        anchor_id_map=anchor_id_map,
        tracev3_file_ids=tracev3_file_ids,
        keep_raw=keep_raw,
    )


def _worker_parse(rel_path: str) -> tuple[tuple[str, str, str, int, int], list[LogEntry]]:
    """Parse one tracev3 (path relative to the logarchive root) → (stats, entries)."""
    root: Path = _WORKER["root"]  # type: ignore[assignment]
    entries: list[LogEntry] = []
    stats = _process_tracev3(
        root / rel_path,
        root,
        _WORKER["strings"],                        # type: ignore[arg-type]
        _WORKER["oversize_cache"],                 # type: ignore[arg-type]
        _WORKER["timesync_data"],                  # type: ignore[arg-type]
        _WORKER["boot_map"],                       # type: ignore[arg-type]
        _WORKER["tracev3_file_ids"][rel_path],     # type: ignore[index]
        _WORKER["anchor_id_map"],                  # type: ignore[arg-type]
        entries.append,
        keep_raw=bool(_WORKER["keep_raw"]),
    )
    return stats, entries
