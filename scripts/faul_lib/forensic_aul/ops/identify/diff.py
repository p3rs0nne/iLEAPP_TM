"""Diff logic for the ``identify`` subcommand.

Given two extracted SQLite databases (baseline + post-action), produce:

  * a CSV containing only the *retained* lines (entries attributable to the
    action), and
  * a SQLite database containing every entry from the action DB whose
    timestamp is after the baseline cutoff, with an ``excluded`` flag column
    so an analyst can re-inspect lines that were filtered out.

Noise definition
----------------
A line in the action DB is considered noise (``excluded = 1``) if either:
  1. its ``timestamp_unix_ns`` is ≤ the baseline cutoff (i.e. it predates
     the moment the action was performed), or
  2. its ``(message, process_name)`` tuple already appears in the baseline.

The cutoff is ``MAX(timestamp_unix_ns)`` from the baseline DB — i.e. the
last log line collected before the operator performed the action.

The CSV output omits category (1) entirely (they predate the action and
carry no information about it) and only the entries from category (2) plus
the retained ones, matching what the analyst wants in front of them.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
from pathlib import Path

from forensic_aul.engine.utils.time import iso8601_from_unix_ns
from forensic_aul.outcomes import DiffResult

log = logging.getLogger(__name__)


# Columns selected per row, in display order. Joined against the lookup tables
# (processes, subsystems, categories, log_levels, event_types) for human
# readability. The ISO timestamp is not stored — it is formatted on read from
# timestamp_unix_ns (the first SELECT column), so it is omitted from the SQL.
# Rows newer than the cutoff OR with the unix_ns=0 failure sentinel: a sentinel
# row cannot be proven to predate the action, so it is surfaced (excluded=0) with
# a note rather than silently dropped. event_order is carried through so the
# tamper signal stays visible in the diff output too (L10).
_CSV_SQL = """
SELECT
    l.timestamp_unix_ns   AS timestamp_unix_ns,
    l.event_order         AS event_order,
    p.name                AS process,
    l.pid                 AS pid,
    l.tid                 AS tid,
    ll.name               AS log_level,
    et.name               AS event_type,
    s.name                AS subsystem,
    c.name                AS category,
    l.message             AS message
FROM logs l
LEFT JOIN processes   p  ON p.id  = l.process_id
LEFT JOIN subsystems  s  ON s.id  = l.subsystem_id
LEFT JOIN categories  c  ON c.id  = l.category_id
LEFT JOIN log_levels  ll ON ll.id = l.log_level_id
LEFT JOIN event_types et ON et.id = l.event_type_id
WHERE l.timestamp_unix_ns > ? OR l.timestamp_unix_ns = 0
ORDER BY l.timestamp_unix_ns ASC, l.id ASC
"""

_CSV_HEADER = [
    "timestamp", "timestamp_unix_ns", "event_order", "process", "pid", "tid",
    "log_level", "event_type", "subsystem", "category", "message", "note",
]


def _baseline_cutoff_ns(baseline_db: Path) -> int:
    """Return the upper-bound timestamp of the baseline DB (nanoseconds).

    Excludes the unix_ns=0 failure sentinel so an all-unresolved baseline raises
    the no-entries error rather than yielding a cutoff of 0 (which would let
    every action row through).
    """
    with sqlite3.connect(str(baseline_db)) as conn:
        row = conn.execute(
            "SELECT MAX(timestamp_unix_ns) FROM logs WHERE timestamp_unix_ns > 0"
        ).fetchone()
    if row is None or row[0] is None:
        raise ValueError(f"baseline DB {baseline_db} contains no log entries")
    return int(row[0])


def _load_baseline_keys(baseline_db: Path) -> set[tuple[str, str]]:
    """Load the (message, process_name) set that defines background noise.

    Process name is resolved via the JOIN so the key is comparable across
    DBs whose `processes.id` values differ.
    """
    keys: set[tuple[str, str]] = set()
    with sqlite3.connect(str(baseline_db)) as conn:
        cur = conn.execute("""
            SELECT l.message, COALESCE(p.name, '')
            FROM logs l
            LEFT JOIN processes p ON p.id = l.process_id
            WHERE l.message IS NOT NULL
        """)
        for msg, proc in cur:
            keys.add((msg, proc))
    return keys


def run_diff(
    baseline_db: Path,
    action_db: Path,
    csv_out: Path,
    sqlite_out: Path,
) -> DiffResult:
    """Diff a post-action database against a baseline and write both outputs.

    Computes the baseline cutoff (``MAX(timestamp_unix_ns)`` over *baseline_db*)
    and the baseline noise set (``(message, process_name)`` tuples), then streams
    every entry from *action_db* newer than the cutoff, classifying each as
    *retained* (attributable to the action) or *excluded* (noise already present
    in the baseline). See the module docstring for the full noise definition.

    Args:
        baseline_db: SQLite database extracted *before* the action was performed.
        action_db: SQLite database extracted *after* the action was performed.
        csv_out: Destination CSV — receives the retained rows only (UTF-8 with BOM
            so Excel auto-detects the encoding). Parent dirs are created.
        sqlite_out: Destination SQLite — receives every post-cutoff row with an
            ``excluded`` flag column, so excluded lines remain re-inspectable. An
            existing file at this path is overwritten.

    Returns:
        A :class:`~forensic_aul.outcomes.DiffResult` with the two output paths and
        the ``retained`` / ``excluded`` counts (*retained* = rows in the CSV,
        *excluded* = rows flagged as baseline noise).

    Raises:
        ValueError: *baseline_db* contains no log entries (no cutoff derivable).
    """
    cutoff_ns = _baseline_cutoff_ns(baseline_db)
    log.info(f"Baseline cutoff (unix_ns): {cutoff_ns}")

    baseline_keys = _load_baseline_keys(baseline_db)
    log.info(f"Baseline noise set: {len(baseline_keys)} unique (message, process) tuples")

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    sqlite_out.parent.mkdir(parents=True, exist_ok=True)
    if sqlite_out.exists():
        sqlite_out.unlink()

    n_retained = 0
    n_excluded = 0

    with sqlite3.connect(str(action_db)) as src, \
            sqlite3.connect(str(sqlite_out)) as dst, \
            csv_out.open("w", newline="", encoding="utf-8-sig") as fp:  # BOM so Excel auto-detects UTF-8

        # Output SQLite schema: identical columns to the CSV plus the flag.
        dst.execute("""
            CREATE TABLE identified_logs (
                id                  INTEGER PRIMARY KEY,
                timestamp           TEXT,
                timestamp_unix_ns   INTEGER,
                event_order         INTEGER,
                process             TEXT,
                pid                 INTEGER,
                tid                 INTEGER,
                log_level           TEXT,
                event_type          TEXT,
                subsystem           TEXT,
                category            TEXT,
                message             TEXT,
                excluded            INTEGER NOT NULL,
                note                TEXT
            )
        """)
        dst.execute(
            "CREATE INDEX idx_identified_logs_excluded ON identified_logs(excluded)"
        )
        dst.execute(
            "CREATE INDEX idx_identified_logs_ts ON identified_logs(timestamp_unix_ns)"
        )

        writer = csv.writer(fp)
        writer.writerow(_CSV_HEADER)

        cur = src.execute(_CSV_SQL, (cutoff_ns,))

        insert_sql = """
            INSERT INTO identified_logs
                (timestamp, timestamp_unix_ns, event_order, process, pid, tid,
                 log_level, event_type, subsystem, category, message, excluded, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        batch: list[tuple] = []
        BATCH = 1_000
        n_unresolved = 0

        for row in cur:
            ts_ns, event_order, proc, pid, tid, lvl, et, sub, cat, msg = row
            if ts_ns == 0:
                # Unresolved timestamp: emit empty ISO (not the 1970 sentinel) and
                # keep it retained (excluded=0) — it cannot be proven pre-cutoff.
                ts = ""
                note = "unresolved timestamp (timestamp_unix_ns=0)"
                excluded = 0
                n_unresolved += 1
            else:
                ts = iso8601_from_unix_ns(ts_ns)
                note = ""
                key = (msg, proc or "")
                excluded = 1 if (msg is not None and key in baseline_keys) else 0

            batch.append((ts, ts_ns, event_order, proc, pid, tid, lvl, et, sub, cat, msg, excluded, note))
            if len(batch) >= BATCH:
                dst.executemany(insert_sql, batch)
                batch.clear()

            if excluded:
                n_excluded += 1
            else:
                writer.writerow([ts, ts_ns, event_order, proc, pid, tid, lvl, et, sub, cat, msg, note])
                n_retained += 1

        if batch:
            dst.executemany(insert_sql, batch)

        dst.commit()

    if n_unresolved:
        log.warning(f"Diff: {n_unresolved} action row(s) had an unresolved timestamp (timestamp_unix_ns=0) — kept as retained with excluded=0 and a note (cannot be proven pre-cutoff)")
    log.info(f"Diff complete: {n_retained} retained, {n_excluded} excluded")
    return DiffResult(
        csv_path=csv_out,
        sqlite_path=sqlite_out,
        retained=n_retained,
        excluded=n_excluded,
    )
