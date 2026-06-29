"""AUL Parser — extract pipeline.

Converts a .logarchive directory into a normalised SQLite database.

Pipeline steps
--------------
1. Forensic hashing of the whole logarchive
2. Schema initialisation (WAL, tables, indexes, FTS5)
3. Insert case_metadata placeholder
4. Parse all *.timesync files
5. Build lazy StringCacheProvider (UUIDText + DSC)
6. Pass 1 — collect Oversize entries from all tracev3 files
7. Pass 2 — parse all tracev3 in order, produce LogEntry rows, write to DB
8. Finalise case_metadata (timestamps, ios_model, ios_build_version)
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Mapping
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from itertools import islice
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.config import BATCH_SIZE
from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import (
    apply_pragmas,
    finalize_deferred_fts,
    finalize_indexes,
    init_schema,
)
from forensic_aul.engine.database.writer import BatchWriter, register_source_file
from forensic_aul.engine.integrity import verify_source_files
from forensic_aul.engine.ios_builds import ios_version_for_build
from forensic_aul.engine.models import TimesyncBoot
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.parser.timesync import (
    merge_timesync_dicts,
    parse_timesync_file,
)
from forensic_aul.engine.utils.progress import ProgressReporter, ProgressSink
from forensic_aul.engine.utils.time import iso8601_from_unix_ns
from forensic_aul.ops.extraction.discovery import (
    _find_timesync_files,
    _find_tracev3_files,
)
from forensic_aul.ops.extraction.oversize_pass import OversizeCache, _collect_oversize
from forensic_aul.ops.extraction.source import prepare_source
from forensic_aul.ops.extraction.timesync_setup import _preinsert_timesync_anchors
from forensic_aul.ops.extraction.tracev3_parse import _process_tracev3
from forensic_aul.ops.extraction.workers import _worker_init, _worker_parse
from forensic_aul.outcomes import ExtractResult

# Relative phase weights for the extract progress bar (ratios, normalised by the
# reporter). Tuned to the observed split on a large extract; finish() covers any
# phase that is skipped (e.g. the FTS rebuild when FTS is incremental).
_EXTRACT_PHASES = [
    ("prepare", 0.08),   # source prep + hashing + timesync + string cache + oversize scan
    ("parse", 0.55),     # pass 2, weighted by tracev3 bytes
    ("ordering", 0.17),  # assign_ordering
    ("index", 0.13),     # finalize_indexes
    ("fts", 0.07),       # deferred FTS rebuild (--fast-fts only)
]

log = logging.getLogger(__name__)


def _ingest_shutdown_log(
    writer: BatchWriter,
    logarchive_root: Path,
    file_hashes: dict[str, str],
) -> int:
    """Parse ``shutdown.log`` (if present) into the shutdown_events tables.

    These are wall-clock-anchored power-off events with no mach time/boot, so they
    live outside the logs/event_order timeline (see extraction/shutdown_log.py).
    Returns the number of shutdown events ingested.
    """
    from forensic_aul.ops.extraction.shutdown_log import find_shutdown_log, parse_shutdown_log

    path = find_shutdown_log(logarchive_root)
    if path is None:
        log.debug("No shutdown.log found — skipping shutdown events")
        return 0
    try:
        events = parse_shutdown_log(path)
    except Exception as exc:  # noqa: BLE001 — a malformed sidecar must not fail the extract
        log.warning(f"shutdown.log parse error in {path.name}: {exc}")
        return 0
    if not events:
        log.info(f"shutdown.log found ({path.name}) but no shutdown events parsed")
        return 0

    sf_id = register_source_file(writer, logarchive_root, path, "shutdown_log", file_hashes)
    for ev in events:
        ev_id = writer.insert_shutdown_event(
            sf_id, ev.unix_ns, ev.iso, ev.delay_seconds, len(ev.clients)
        )
        if ev.clients:
            writer.insert_shutdown_clients(
                ev_id, [(c.pid, c.process_path, c.lingered_seconds) for c in ev.clients]
            )
    return len(events)


# ── Public entry point ────────────────────────────────────────────────────────

def run_extract(
    logarchive: Path | Mapping[str, Path],
    db_path: Path,
    *,
    case_number: str | None = None,
    imei: str | None = None,
    exhibit_number: str | None = None,
    analyst_name: str | None = None,
    notes: str | None = None,
    batch_size: int = BATCH_SIZE,
    work_dir: Path | None = None,
    fast_fts: bool = False,
    fast_write: bool = False,
    fts: bool = True,
    keep_raw: bool = False,
    jobs: int = 1,
    overwrite: bool = False,
    progress: ProgressSink | None = None,
) -> ExtractResult:
    """Full extract pipeline: source → SQLite.

    This is the main entry point called by the CLI. *logarchive* may be a
    ``.logarchive`` directory, a sysdiagnose ``.tar.gz``, a full-file-system
    ``.zip``, or a mapping of two already-uncompressed folders
    ``{"diagnostics": dir, "uuidtext": dir}`` — the source-preparation layer
    normalises all of them to a logarchive layout before parsing (see
    forensic_aul/ops/extraction/source.py). Archives / loose dirs are materialised
    into *work_dir* (kept) or an auto-cleaned temp dir.

    *jobs* is the total process budget for parsing: ``1`` (default) parses
    in-process; ``N`` uses ``N-1`` worker processes plus the writer (this main
    process), so total processes ≈ one per CPU core. The result is identical
    regardless of *jobs* (ordering is assigned post-load; see database/ordering.py).

    If *db_path* already exists the call refuses to proceed unless *overwrite* is
    True — extracting into an existing database would silently merge two
    acquisitions into one file. With *overwrite* the existing database (and its
    ``-wal`` / ``-shm`` sidecars) is removed first so the run starts clean.

    Returns:
        An :class:`~forensic_aul.outcomes.ExtractResult` bundling the output
        ``db_path``, the ``metadata_id`` (to seal the log-file hash later), and
        the run facts (entry/error counts, device model, iOS build/version, boot
        UUID, time range, source type and SHA-256).

    Raises:
        FileExistsError: *db_path* exists and *overwrite* is False.
    """
    # Fail fast (before the expensive source hashing) and never silently append
    # a second acquisition into an existing database. The actual removal is
    # deferred until just before we open the connection (see below), so a failure
    # during source preparation cannot destroy a pre-existing database.
    if db_path.exists() and not overwrite:
        raise FileExistsError(
            f"{db_path} already exists; pass overwrite=True to replace it "
            "(extracting into an existing database would merge two acquisitions)"
        )

    _t0 = time.monotonic()
    reporter = ProgressReporter(progress, _EXTRACT_PHASES)
    reporter.phase("prepare", "hashing source")

    # ── Step 1: Source preparation + forensic hashing ─────────────────────
    log.info("─── Step 1/7 : Source preparation + hashing ──────────────────")
    log.info("Preparing source (extracting archives may take a moment)…")
    if isinstance(logarchive, Mapping):
        log.debug("Source dirs : %s", {k: str(v) for k, v in logarchive.items()})
    else:
        log.debug("Source path : %s", Path(logarchive).resolve())
    _t_hash = time.monotonic()
    prepared = prepare_source(logarchive, work_dir=work_dir)
    log.info(f"Source type        : {prepared.source_type.value}")
    if prepared.archive_fingerprint is not None:
        log.info(f"Archive fingerprint: {prepared.archive_fingerprint}  (pre-run snapshot)")
        if prepared.is_temporary:
            log.info("Work dir           : temporary (auto-cleaned after run)")
        else:
            log.info(f"Work dir (kept)    : {prepared.logarchive_root}")
    log.info(f"Content SHA-256    : {prepared.content_sha256}  ({len(prepared.file_hashes)} files hashed in {time.monotonic() - _t_hash:.1f} s)")
    log.debug("Per-file hashes:")
    for rel_path, digest in sorted(prepared.file_hashes.items()):
        log.debug("  %s  %s", digest, rel_path)

    # ── Step 2: Database setup ────────────────────────────────────────────
    log.info("─── Step 2/7 : Database initialisation ─────────────────────────")
    log.debug("Output database : %s", db_path.resolve())
    # Source preparation succeeded, so it is now safe to clear any existing DB
    # (and its WAL/SHM sidecars) and start clean — deferred from the entry guard
    # so a prep failure could not have destroyed a pre-existing database.
    if overwrite:
        for sidecar in (db_path, db_path.with_name(db_path.name + "-wal"),
                        db_path.with_name(db_path.name + "-shm")):
            sidecar.unlink(missing_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        result = _run_extract_inner(
            conn=conn,
            logarchive=prepared.logarchive_root,
            db_path=db_path,
            case_number=case_number,
            imei=imei,
            exhibit_number=exhibit_number,
            analyst_name=analyst_name,
            notes=notes,
            batch_size=batch_size,
            fast_fts=fast_fts,
            fast_write=fast_write,
            fts=fts,
            keep_raw=keep_raw,
            jobs=jobs,
            logarchive_sha256=prepared.content_sha256,
            file_hashes=prepared.file_hashes,
            source_path=str(prepared.original_path),
            logarchive_path=prepared.recorded_logarchive_path,
            source_type=prepared.source_type.value,
            archive_fingerprint=prepared.archive_fingerprint,
            ios_product_version=prepared.ios_product_version,
            reporter=reporter,
            t0=_t0,
        )
        reporter.finish("complete")
        # ── Integrity attestation (after) ─────────────────────────────────
        # Re-check the archive fingerprint now the run is complete: we only ever
        # opened the evidence read-only, so a mismatch means it was modified
        # externally during the run and the result must be treated with caution.
        if prepared.archive_fingerprint is not None:
            if prepared.verify_unchanged():
                log.info("Archive integrity re-check : PASS — unchanged since pre-run snapshot")
            else:
                log.warning(f"Archive integrity re-check : FAIL — {prepared.original_path} changed during the run!")
        return result
    finally:
        conn.close()
        prepared.cleanup()


def _run_extract_inner(
    *,
    conn: sqlite3.Connection,
    logarchive: Path,
    db_path: Path,
    case_number: str | None,
    imei: str | None,
    exhibit_number: str | None,
    analyst_name: str | None,
    notes: str | None,
    batch_size: int,
    fast_fts: bool,
    fast_write: bool,
    fts: bool,
    keep_raw: bool,
    jobs: int,
    logarchive_sha256: str,
    file_hashes: dict[str, str],
    source_path: str,
    logarchive_path: str,
    source_type: str,
    archive_fingerprint: str | None,
    ios_product_version: str | None,
    reporter: ProgressReporter,
    t0: float,
) -> ExtractResult:
    """Body of run_extract — connection lifetime is owned by the caller."""
    # Durability: NORMAL (default) never corrupts the DB; --fast-write uses OFF
    # for speed at the cost of power-loss safety. sort_threads parallelises the
    # finaliser sorts (index builds + ordering) across the same core budget.
    apply_pragmas(
        conn,
        synchronous="OFF" if fast_write else "NORMAL",
        sort_threads=max(0, jobs),
    )
    # Indexes are always deferred to the end of the run (built by finalize_indexes):
    # cheap on a finished table, and an interrupted run still has complete, correct
    # (just unindexed) data. FTS is on by default (--no-fts opts out); when on it
    # stays incremental unless --fast-fts defers the rebuild.
    fts5_ok = init_schema(
        conn, enable_fts5=fts, defer_fts_triggers=fast_fts, create_indexes=False
    )
    log.info(f'Schema created  : WAL mode (sync={"OFF" if fast_write else "NORMAL"}), indexes deferred, FTS5={"enabled" if fts5_ok else ("disabled" if not fts else "unavailable")}{" (deferred rebuild)" if fast_fts and fts5_ok else ""}, raw_data={"kept" if keep_raw else "dropped"}, batch_size={batch_size}')

    writer = BatchWriter(conn, batch_size=batch_size)

    total_entries, total_errors, ios_model, ios_build_version, boot_uuid, metadata_id = (
        _run_parse(
            conn=conn,
            writer=writer,
            logarchive=logarchive,
            case_number=case_number,
            imei=imei,
            exhibit_number=exhibit_number,
            analyst_name=analyst_name,
            notes=notes,
            batch_size=batch_size,
            keep_raw=keep_raw,
            jobs=jobs,
            logarchive_sha256=logarchive_sha256,
            file_hashes=file_hashes,
            source_path=source_path,
            logarchive_path=logarchive_path,
            source_type=source_type,
            archive_fingerprint=archive_fingerprint,
            reporter=reporter,
        )
    )

    return _finalise(
        conn=conn,
        writer=writer,
        logarchive=logarchive,
        db_path=db_path,
        fast_fts=fast_fts,
        fts=fts,
        fts5_ok=fts5_ok,
        keep_raw=keep_raw,
        logarchive_sha256=logarchive_sha256,
        file_hashes=file_hashes,
        source_type=source_type,
        ios_product_version=ios_product_version,
        reporter=reporter,
        t0=t0,
        total_entries=total_entries,
        total_errors=total_errors,
        ios_model=ios_model,
        ios_build_version=ios_build_version,
        boot_uuid=boot_uuid,
        metadata_id=metadata_id,
    )


def _run_parse(
    *,
    conn: sqlite3.Connection,
    writer: BatchWriter,
    logarchive: Path,
    case_number: str | None,
    imei: str | None,
    exhibit_number: str | None,
    analyst_name: str | None,
    notes: str | None,
    batch_size: int,
    keep_raw: bool,
    jobs: int,
    logarchive_sha256: str,
    file_hashes: dict[str, str],
    source_path: str,
    logarchive_path: str,
    source_type: str,
    archive_fingerprint: str | None,
    reporter: ProgressReporter,
) -> tuple[int, int, str, str, str, int]:
    """Steps 3-7: metadata placeholder, timesync, string cache, oversize, parse loop.

    Returns (total_entries, total_errors, ios_model, ios_build_version, boot_uuid, metadata_id).
    """
    # ── Step 3: Case metadata ─────────────────────────────────────────────
    log.info("─── Step 3/7 : Case metadata ────────────────────────────────────")
    metadata_id = writer.insert_case_metadata(
        case_number=case_number,
        imei=imei,
        exhibit_number=exhibit_number,
        analyst_name=analyst_name,
        notes=notes,
        source_path=source_path,
        logarchive_path=logarchive_path,
        logarchive_sha256=logarchive_sha256,
        source_type=source_type,
        archive_fingerprint=archive_fingerprint,
        tool_version=__version__,
    )
    conn.commit()
    log.info(f"Case metadata inserted  : id={metadata_id}  case={case_number}  imei={imei}")
    if exhibit_number:
        log.info(f"  Exhibit  : {exhibit_number}")
    if analyst_name:
        log.info(f"  Analyst  : {analyst_name}")

    # ── Step 4: Timesync ──────────────────────────────────────────────────
    log.info("─── Step 4/7 : Timesync files ───────────────────────────────────")
    timesync_data: dict[str, TimesyncBoot] = {}
    ts_files = _find_timesync_files(logarchive)
    boot_uuid_to_timesync_file_id: dict[str, int] = {}
    # Physical boot order for event_order: first-appearance rank as we walk the
    # name-sorted timesync files (append-only, sequence-numbered) and each file's
    # boots in offset order. WHY not boot_time: that is wall-clock at boot, so a
    # clock reset could reorder boots — physical layout is tamper-resilient.
    boot_rank_by_uuid: dict[str, int] = {}
    log.info(f"Found {len(ts_files)} timesync file(s)")
    for ts_file in ts_files:
        try:
            merged = parse_timesync_file(ts_file)
            if merged:
                # Register this timesync file once and stamp its source-file id
                # onto every boot header and record it parsed, so anchor
                # provenance survives a boot UUID spanning multiple files.
                ts_file_id = register_source_file(writer, logarchive, ts_file, "timesync", file_hashes)
                for boot_uuid_key, boot in merged.items():
                    boot.timesync_file_id = ts_file_id
                    for record in boot.timesync:
                        record.timesync_file_id = ts_file_id
                    # First file to mention a boot owns its coarse map entry; the
                    # real per-anchor provenance now travels on each record, so
                    # last-wins (the old bug) is no longer needed here.
                    boot_uuid_to_timesync_file_id.setdefault(boot_uuid_key, ts_file_id)
                    if boot_uuid_key not in boot_rank_by_uuid:
                        boot_rank_by_uuid[boot_uuid_key] = len(boot_rank_by_uuid)
                # WHY merge_timesync_dicts not dict.update: a boot UUID present in
                # a second .timesync file must APPEND its records, not replace the
                # earlier list (forensic loss of anchors otherwise).
                merge_timesync_dicts(timesync_data, merged)
                log.debug(
                    "  %s  →  %d boot record(s)  file_id=%d",
                    ts_file.name, len(merged), ts_file_id,
                )
        except Exception as exc:
            log.warning(f"  {ts_file.name}  parse error: {exc}")
    log.info(f"Timesync loaded : {len(timesync_data)} boot UUID(s)  covering {sum(len(b.timesync) for b in timesync_data.values())} record(s) total")
    # Register every known boot with its physical rank now, so the writer resolves
    # boot_id from its cache during the parse and assign_ordering can sort on the
    # integer boots.rank. Insert in rank order (first-appearance) for tidy ids.
    for boot_uuid_key, rank in sorted(boot_rank_by_uuid.items(), key=lambda kv: kv[1]):
        writer.register_boot(boot_uuid_key, rank)

    # Pre-insert all selectable anchors so parser workers resolve
    # timesync_anchor_id with a pure map lookup (no DB).
    anchor_id_map = _preinsert_timesync_anchors(
        writer, timesync_data, boot_uuid_to_timesync_file_id
    )
    log.info(f"Timesync anchors pre-inserted : {len(anchor_id_map)}")

    # ── Step 5: String cache (UUIDText + DSC) ─────────────────────────────
    log.info("─── Step 5/7 : String cache (UUIDText + DSC) ───────────────────")
    strings = StringCacheProvider(logarchive)
    strings.load(writer, logarchive, file_hashes)
    # StringCacheProvider already logs its summary at INFO

    # ── Step 6: Pass 1 — Oversize entries ────────────────────────────────
    log.info("─── Step 6/7 : Pass 1 — Oversize scan ──────────────────────────")
    tracev3_files = _find_tracev3_files(logarchive)
    log.info(f"Found {len(tracev3_files)} tracev3 file(s)  (Persist / Special / Signpost order)")
    for f in tracev3_files:
        log.debug("  %s  (%d B)", f.relative_to(logarchive), f.stat().st_size)

    # Pre-register every tracev3 file now, in canonical order, so tracev3_file_id
    # is fixed before parsing (workers receive it; source_order/event_order rely on
    # the canonical id order). Keyed by posix relpath so it is picklable + stable.
    tracev3_file_ids: dict[str, int] = {}
    for path in tracev3_files:
        rel = path.relative_to(logarchive).as_posix()
        tracev3_file_ids[rel] = register_source_file(
            writer, logarchive, path, "tracev3", file_hashes
        )
    # Persist source_files + anchors before parsing (workers read no DB, but this
    # keeps the on-disk state consistent and the WAL small).
    conn.commit()

    oversize_cache: OversizeCache = _collect_oversize(tracev3_files, strings)
    log.info(f"Oversize cache  : {len(oversize_cache)} entry(ies) collected")

    # ── Step 7: Pass 2 — Main parse ───────────────────────────────────────
    log.info("─── Step 7/7 : Pass 2 — Main parse ─────────────────────────────")
    ios_model: str = ""
    ios_build_version: str = ""
    boot_uuid: str = ""
    total_entries: int = 0
    total_errors: int = 0

    def _aggregate(stats: tuple[str, str, str, int, int]) -> None:
        nonlocal ios_model, ios_build_version, boot_uuid, total_entries, total_errors
        b_uuid, model, build, n_written, n_err = stats
        total_entries += n_written
        total_errors += n_err
        if b_uuid and not boot_uuid:
            boot_uuid = b_uuid
        if model and not ios_model:
            ios_model = model
        if build and not ios_build_version:
            ios_build_version = build

    rels = [p.relative_to(logarchive).as_posix() for p in tracev3_files]

    # Progress: weight the parse by tracev3 byte size (files vary ~1000x in entry
    # count, so byte size advances the bar far more smoothly than file count).
    reporter.phase("parse")
    _sizes = {rel: max(1, p.stat().st_size) for p, rel in zip(tracev3_files, rels)}
    _total_bytes = sum(_sizes.values()) or 1
    _done_bytes = 0

    if jobs <= 1:
        # Serial in-process path: parse → writer.add directly.
        for i, (path, rel) in enumerate(zip(tracev3_files, rels), 1):
            log.info(f"[{i}/{len(tracev3_files)}] {rel}")
            _aggregate(_process_tracev3(
                path, logarchive, strings, oversize_cache,
                timesync_data, boot_uuid_to_timesync_file_id,
                tracev3_file_ids[rel], anchor_id_map, writer.add,
                keep_raw=keep_raw,
            ))
            _done_bytes += _sizes[rel]
            reporter.update(_done_bytes / _total_bytes, f"{i}/{len(tracev3_files)}")
    else:
        n_workers = max(1, jobs - 1)
        log.info(f"Parsing in parallel : {n_workers} worker process(es) + 1 writer (jobs={jobs})")
        with ProcessPoolExecutor(
            max_workers=n_workers,
            initializer=_worker_init,
            initargs=(
                logarchive, timesync_data, oversize_cache,
                boot_uuid_to_timesync_file_id, anchor_id_map,
                tracev3_file_ids, strings.uuid_file_ids(), keep_raw,
            ),
        ) as ex:
            # Bound the number of in-flight files so completed-but-unwritten
            # results cannot pile up in this (the sole writer) process.
            # WHY: each worker returns its file's *entire* list of LogEntry
            # objects back here to be written. If we submit every file at once,
            # the workers race ahead of the single writer and their returned
            # lists accumulate in this process — observed at 38 GB of resident
            # memory on a 2.5 GB archive, which then thrashes swap. Keeping at
            # most ~2x workers' worth of files in flight keeps every core fed
            # while capping resident results to a handful of files' entries.
            # The output is identical regardless of the window size.
            max_in_flight = max(2, n_workers * 2)
            rel_iter = iter(rels)
            in_flight: dict[object, str] = {
                ex.submit(_worker_parse, rel): rel
                for rel in islice(rel_iter, max_in_flight)
            }
            done = 0
            while in_flight:
                finished, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                for fut in finished:
                    rel = in_flight.pop(fut)
                    stats, entries = fut.result()
                    # Single writer (this process) — one DB connection, no contention.
                    writer.add_batch(entries)
                    _aggregate(stats)
                    done += 1
                    _done_bytes += _sizes[rel]
                    reporter.update(_done_bytes / _total_bytes, f"{done}/{len(rels)}")
                    log.info(f"[{done}/{len(rels)}] {rel}  ({stats[3]} entries)")
                    # Refill: keep the in-flight window full until files run out.
                    nxt = next(rel_iter, None)
                    if nxt is not None:
                        in_flight[ex.submit(_worker_parse, nxt)] = nxt

    writer.flush()
    log.info(f"Parse complete  : {total_entries} total entries written  {total_errors} parse error(s)")
    if total_errors:
        log.warning(f"{total_errors} parse error(s) encountered — run with --verbose for details")
    if writer.write_errors:
        # Loud and explicit: the store is knowingly incomplete. Each dropped row
        # was already logged at ERROR with its source provenance.
        log.warning(f"{writer.write_errors} log row(s) could NOT be stored by the database and were dropped — the database is incomplete; see the ERROR lines above for the affected records.")

    # ── Shutdown events (shutdown.log → shutdown_events/_clients) ───────────
    # Wall-clock-anchored power-off events; kept out of the logs/event_order
    # timeline and correlated to logs by wall-clock time.
    n_shutdowns = _ingest_shutdown_log(writer, logarchive, file_hashes)
    if n_shutdowns:
        log.info(f"Shutdown events : {n_shutdowns} parsed from shutdown.log")
    conn.commit()

    return total_entries, total_errors, ios_model, ios_build_version, boot_uuid, metadata_id


def _finalise(
    *,
    conn: sqlite3.Connection,
    writer: BatchWriter,
    logarchive: Path,
    db_path: Path,
    fast_fts: bool,
    fts: bool,
    fts5_ok: bool,
    keep_raw: bool,
    logarchive_sha256: str,
    file_hashes: dict[str, str],
    source_type: str,
    ios_product_version: str | None,
    reporter: ProgressReporter,
    t0: float,
    total_entries: int,
    total_errors: int,
    ios_model: str,
    ios_build_version: str,
    boot_uuid: str,
    metadata_id: int,
) -> ExtractResult:
    """Ordering, indexes, FTS, integrity re-check, metadata update; returns ExtractResult."""
    # ── Forensic ordering ──────────────────────────────────────────────────
    # Assign source_order (per-file physical) + event_order (boot, monotonic mach)
    # now that every row is loaded — independent of insertion order, so it is
    # identical whether the parse ran serially or across worker processes.
    reporter.phase("ordering", "merging timeline")
    log.info("Assigning forensic ordering (source_order + event_order)…")
    assign_ordering(conn)

    # ── Build secondary indexes (deferred from schema setup) ───────────────
    # One sorted build per index over the finished table — far cheaper than
    # maintaining every index on each INSERT during the load. Runs after ordering
    # so the event_order / source_order indexes build on their final values.
    reporter.phase("index", "building indexes")
    log.info("Building secondary indexes…")
    _t_idx = time.monotonic()
    finalize_indexes(conn)
    conn.commit()
    log.info(f"Secondary indexes built in {time.monotonic() - _t_idx:.1f} s")

    # ── Deferred FTS5 build (--fast-fts) ───────────────────────────────────
    # The bulk load ran without FTS maintenance triggers; build the index once
    # now and install the triggers for subsequent mutations.
    if fast_fts and fts5_ok:
        reporter.phase("fts", "full-text index")
        log.info("Building FTS5 index (deferred rebuild)…")
        _t_fts = time.monotonic()
        finalize_deferred_fts(conn)
        log.info(f"FTS5 index built in {time.monotonic() - _t_fts:.1f} s")

    # ── Per-file integrity re-verification ─────────────────────────────────
    # Re-hash every registered source file now the run is complete and store the
    # result per file (source_files.sha256_after / integrity_ok). This is the
    # "after" half of the per-file chain of custody: a file that changed under us
    # is flagged individually, while every other file's parsed data stays usable.
    log.info("Re-verifying per-file integrity (end-of-run re-hash)…")
    _t_intg = time.monotonic()
    files_ok, files_changed, files_unverifiable = verify_source_files(conn, logarchive)
    log.info(f"Integrity re-check : {files_ok} unchanged, {files_changed} changed, {files_unverifiable} unverifiable  ({time.monotonic() - _t_intg:.1f} s)")
    if files_changed:
        log.warning(f"{files_changed} source file(s) CHANGED during the run — their parsed data is suspect (see source_files.integrity_ok = 0); other files are unaffected")

    # ── Compute log time bounds ────────────────────────────────────────────
    # The displayed range is the wall-clock span, so take MIN/MAX of the indexed
    # timestamp_unix_ns (one index-aided pass each) and format to ISO on read.
    # The ISO string is no longer stored (see schema.py / iso8601_from_unix_ns).
    # WHY ``WHERE timestamp_unix_ns > 0``: a failed resolution is persisted as the
    # sentinel 0 (visible by design). Without the guard, a single unresolved entry
    # makes MIN read 1970-01-01 and corrupts the reported log_start_time. The
    # sentinel rows stay in the DB; only this summary read excludes them.
    first_ts: str | None = None
    last_ts: str | None = None
    bounds = conn.execute(
        "SELECT MIN(timestamp_unix_ns), MAX(timestamp_unix_ns) FROM logs "
        "WHERE timestamp_unix_ns > 0"
    ).fetchone()
    if bounds and bounds[0] is not None:
        first_ts = iso8601_from_unix_ns(bounds[0])
    if bounds and bounds[1] is not None:
        last_ts = iso8601_from_unix_ns(bounds[1])
    unresolved = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE timestamp_unix_ns = 0"
    ).fetchone()[0]
    if unresolved:
        log.warning(f'Unresolved timestamps : {unresolved} entr{"y" if unresolved == 1 else "ies"} have timestamp_unix_ns=0 (excluded from the reported time range; rows kept in the DB)')
    log.info(f"Log time range  : {first_ts}  →  {last_ts}")

    # ── Resolve iOS version ────────────────────────────────────────────────
    # Priority: authoritative SystemVersion.plist (FFS/sysdiagnose) → best-effort
    # build-code table (bare logarchive dir) → None (keep just the build code).
    ios_version = ios_product_version or ios_version_for_build(ios_build_version)
    if ios_version:
        log.info(f'iOS version     : {ios_version}  (build {ios_build_version or "?"})')

    # ── Finalise case_metadata ─────────────────────────────────────────────
    writer.update_case_metadata(
        metadata_id,
        ios_model=ios_model,
        ios_build_version=ios_build_version,
        ios_version=ios_version,
        log_start_time=first_ts,
        log_end_time=last_ts,
    )
    conn.commit()

    elapsed = time.monotonic() - t0
    log.info("═" * 72)
    log.info("Extract complete")
    log.info(f'  Device model      : {ios_model or "(unknown)"}')
    log.info(f'  Build version     : {ios_build_version or "(unknown)"}')
    log.info(f'  Boot UUID         : {boot_uuid or "(unknown)"}')
    log.info(f"  Log entries       : {total_entries}")
    log.info(f"  Time range        : {first_ts}  →  {last_ts}")
    log.info(f"  Parse errors      : {total_errors}")
    log.info(f"  Elapsed           : {elapsed:.1f} s")
    log.info(f"  Output database   : {db_path.resolve()}")
    log.info(f"  Logarchive SHA-256: {logarchive_sha256}")
    log.info("  Log file SHA-256  : (computed after log is closed)")
    log.info("═" * 72)

    return ExtractResult(
        db_path=db_path,
        metadata_id=metadata_id,
        entry_count=total_entries,
        parse_errors=total_errors,
        write_errors=writer.write_errors,
        source_type=source_type,
        source_sha256=logarchive_sha256,
        device_model=ios_model or None,
        ios_build=ios_build_version or None,
        ios_version=ios_version,
        boot_uuid=boot_uuid or None,
        time_range=(first_ts, last_ts),
        source_files_verified=files_ok,
        source_files_changed=files_changed,
        source_files_unverifiable=files_unverifiable,
    )
