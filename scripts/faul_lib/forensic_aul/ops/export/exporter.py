"""Filtered export of an analysis database to CSV / JSON / JSONL.

Defines : the export logic — ``run_export`` plus the ``ExportFilters`` container
          that decouples it from any CLI argument parser. Knowledge-base aware:
          when annotations exist on the rows being exported, every extracted value
          label (from the ``extracted_values`` table) becomes its own column (CSV)
          or a key in the per-row ``extracted_values`` object (JSON).
Used by : launcher/cmds/export_cmd.py (argparse glue → ``run_export``) and any
          external caller importing ``forensic_aul.ops.export``.
Uses    : the standard library only (sqlite3, csv, json, datetime, re).

A row is emitted once per matching log entry; multiple annotations / extracted
values on the same log are merged into that one row (distinct values for the same
label are joined with "; ").

Errors are raised (``ValueError`` / ``FileNotFoundError``) rather than turned into
exit codes — the CLI wrapper maps them to process exit status and user messages.
"""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from forensic_aul.outcomes import ExportResult
from forensic_aul.engine.utils.time import iso8601_from_unix_ns, parse_duration_seconds

log = logging.getLogger(__name__)


# ── Filters / output options ──────────────────────────────────────────────────

@dataclass
class ExportFilters:
    """Filters and output options for :func:`run_export`.

    Mirrors the CLI flags but is independent of argparse so the export logic can
    be driven programmatically (GUI, scripts, tests) as well as from the CLI.
    List fields are OR-combined within a field and AND-combined across fields.
    """

    fmt: str | None = None              # "csv" / "json" / "jsonl"; None → infer from output suffix
    time_from: str | None = None        # ISO 8601 lower bound (inclusive)
    time_to: str | None = None          # ISO 8601 upper bound (exclusive)
    last: str | None = None             # shortcut for time_from = now - DURATION (10m/1h/24h/7d)
    process: list[str] | None = None
    subsystem: list[str] | None = None
    level: list[str] | None = None
    grep: str | None = None             # SQL LIKE pattern on the message column
    signature: list[str] | None = None
    action: str | None = None           # case-insensitive substring of the annotation action
    tag: list[str] | None = None
    annotated_only: bool = False
    include_fields: bool = True         # emit extracted_fields columns/objects


# ── Public entry point ────────────────────────────────────────────────────────

def run_export(
    database: Path,
    output: Path,
    filters: ExportFilters | None = None,
) -> ExportResult:
    """Export rows from *database* to *output*.

    *database* is a SQLite store produced by ``run_extract`` (and optionally
    annotated by ``annotate_database``). The output format is taken from
    ``filters.fmt`` or inferred from *output*'s suffix.

    Returns:
        An :class:`~forensic_aul.outcomes.ExportResult` with the ``output_path``,
        the number of ``rows`` written, and the resolved ``fmt``.

    Raises:
        FileNotFoundError: *database* does not exist.
        ValueError: the format cannot be determined, a filter value is malformed,
            or a knowledge-base filter is requested on a database with no
            annotations.
    """
    f = filters or ExportFilters()

    if not database.is_file():
        raise FileNotFoundError(f"{database} is not a file")

    fmt = f.fmt or _infer_format(output)
    if fmt is None:
        raise ValueError(f"cannot infer format from {output.name}; set ExportFilters.fmt")

    time_from_ns = _to_unix_ns(f.time_from) if f.time_from else None
    time_to_ns = _to_unix_ns(f.time_to) if f.time_to else None
    if f.last is not None:
        sec = parse_duration_seconds(f.last)
        if sec is None:
            raise ValueError(f"bad duration value {f.last!r}")
        cutoff = int((datetime.now(tz=timezone.utc) - timedelta(seconds=sec)).timestamp() * 1_000_000_000)
        time_from_ns = cutoff if time_from_ns is None else max(time_from_ns, cutoff)

    conn = sqlite3.connect(str(database))
    try:
        rows = _run(conn, output, f, fmt, time_from_ns, time_to_ns)
    finally:
        conn.close()
    return ExportResult(output_path=output, rows=rows, fmt=fmt)


def _run(
    conn: sqlite3.Connection,
    output: Path,
    f: ExportFilters,
    fmt: str,
    time_from_ns: int | None,
    time_to_ns: int | None,
) -> int:
    has_kb = _has_kb_tables(conn)

    # Annotation-based filters require the KB tables to exist.
    if not has_kb and (f.signature or f.action or f.tag or f.annotated_only):
        raise ValueError("this database has no KB annotations — run `annotate` first")

    where, params = _build_where(conn, f, time_from_ns, time_to_ns, has_kb=has_kb)

    # Discover the universe of extracted labels (only relevant when include_fields).
    labels: list[str] = []
    if f.include_fields and has_kb:
        labels = _discover_labels(conn, where, params)
        log.info(f"Export will emit {len(labels)} extracted-value column(s)")

    output.parent.mkdir(parents=True, exist_ok=True)

    include_fields = f.include_fields and has_kb
    if fmt == "csv":
        n = _write_csv(conn, output, where, params, labels, include_fields, has_kb=has_kb)
    elif fmt == "json":
        n = _write_json(conn, output, where, params, include_fields, has_kb=has_kb, jsonl=False)
    else:
        n = _write_json(conn, output, where, params, include_fields, has_kb=has_kb, jsonl=True)

    return n


# ── Filter construction ──────────────────────────────────────────────────────

def _has_kb_tables(conn: sqlite3.Connection) -> bool:
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name IN ('log_annotations', 'kb_signatures')"
    ).fetchall()
    return len(rows) == 2


def _build_where(
    conn: sqlite3.Connection,
    f: ExportFilters,
    time_from_ns: int | None,
    time_to_ns: int | None,
    *,
    has_kb: bool,
) -> tuple[str, list]:
    """Build the WHERE clause that restricts which `logs.id` to export.

    Annotation-based filters are expressed via EXISTS subqueries so that
    matching logs still expose ALL their annotations in the output (not
    only the one that triggered the filter).
    """
    clauses: list[str] = []
    params: list = []

    # Time filters exclude the unix_ns=0 failure sentinel: an unresolved row
    # cannot be proven to fall in the requested window. A ``>= positive`` bound
    # already drops 0; a to-only bound needs the explicit guard. With no time
    # bound at all, sentinel rows are included (nothing to prove them out of).
    if time_from_ns is not None:
        clauses.append("l.timestamp_unix_ns >= ?"); params.append(time_from_ns)
    if time_to_ns is not None:
        clauses.append("l.timestamp_unix_ns <  ?"); params.append(time_to_ns)
        if time_from_ns is None:
            clauses.append("l.timestamp_unix_ns > 0")

    if f.process:
        ids = _lookup_ids(conn, "processes", f.process)
        clauses.append(_in_clause("l.process_id", ids))
        params.extend(ids)
    if f.subsystem:
        ids = _lookup_ids(conn, "subsystems", f.subsystem)
        clauses.append(_in_clause("l.subsystem_id", ids))
        params.extend(ids)
    if f.level:
        # log_level is normalised: resolve the requested names to log_levels.id and
        # filter on the FK (same pattern as process/subsystem above).
        ids = _lookup_ids(conn, "log_levels", f.level)
        clauses.append(_in_clause("l.log_level_id", ids))
        params.extend(ids)
    if f.grep:
        clauses.append("l.message LIKE ?"); params.append(f.grep)

    # Annotation filters
    annot_filters: list[str] = []
    annot_params: list = []
    if f.signature:
        ph = ",".join("?" * len(f.signature))
        annot_filters.append(f"kbs.signature_id IN ({ph})")
        annot_params.extend(f.signature)
    if f.action:
        annot_filters.append("LOWER(kbs.action) LIKE ?")
        annot_params.append(f"%{f.action.lower()}%")
    if f.tag:
        # tags column stores a JSON list. json_each lets us match any element.
        ph = ",".join("?" * len(f.tag))
        annot_filters.append(
            "EXISTS (SELECT 1 FROM json_each(kbs.tags) je WHERE je.value IN (" + ph + "))"
        )
        annot_params.extend(f.tag)

    if f.annotated_only or annot_filters:
        cond = " AND ".join(annot_filters) if annot_filters else "1=1"
        clauses.append(f"""
            EXISTS (
                SELECT 1
                FROM log_annotations la
                JOIN kb_signatures kbs ON kbs.id = la.kb_signature_id
                WHERE la.log_id = l.id AND {cond}
            )
        """)
        params.extend(annot_params)

    where = (" AND ".join(clauses)) if clauses else "1=1"
    return where, params


def _lookup_ids(conn: sqlite3.Connection, table: str, names: list[str]) -> list[int]:
    out: list[int] = []
    for n in names:
        row = conn.execute(f"SELECT id FROM {table} WHERE name = ?", (n,)).fetchone()
        if row is not None:
            out.append(row[0])
    if not out:
        # Force a no-match. -1 is never an inserted id (PK starts at 1).
        return [-1]
    return out


def _in_clause(col: str, ids: list[int]) -> str:
    return f"{col} IN ({','.join('?' * len(ids))})"


# ── Column discovery ──────────────────────────────────────────────────────────

def _discover_labels(
    conn: sqlite3.Connection,
    where: str,
    params: list,
) -> list[str]:
    """Return the sorted distinct extracted-value labels among matching logs.

    These become one CSV column each (and one key each in the JSON
    ``extracted_values`` object). Sorted for a stable, reproducible column order.
    """
    sql = f"""
        SELECT DISTINCT ev.label
        FROM logs l
        JOIN log_annotations la  ON la.log_id = l.id
        JOIN extracted_values ev ON ev.log_annotation_id = la.id
        WHERE {where}
        ORDER BY ev.label
    """
    return [row[0] for row in conn.execute(sql, params)]


# ── CSV writer ────────────────────────────────────────────────────────────────

# ``event_order`` is the forensic ordering rank (monotonic with physical layout);
# it is emitted so the tamper signal — wall-clock going backwards while
# event_order keeps rising — is visible in the primary analyst output.
_BASE_COLUMNS = [
    "timestamp", "timestamp_unix_ns", "event_order", "process", "pid", "tid",
    "log_level", "event_type", "subsystem", "category", "message",
    "matched_signatures",
]


def _write_csv(
    conn: sqlite3.Connection,
    out: Path,
    where: str,
    params: list,
    labels: list[str],
    include_fields: bool,
    *,
    has_kb: bool,
) -> int:
    extra_cols = list(labels) if include_fields else []
    header = list(_BASE_COLUMNS) + extra_cols

    n = 0
    with out.open("w", newline="", encoding="utf-8-sig") as fp:  # BOM so Excel auto-detects UTF-8
        w = csv.writer(fp)
        w.writerow(header)
        for log_row in _iter_logs(conn, where, params, has_kb=has_kb):
            row = [
                log_row.timestamp_iso, log_row.timestamp_unix_ns,
                log_row.event_order,
                log_row.process, log_row.pid, log_row.tid,
                log_row.log_level, log_row.event_type,
                log_row.subsystem, log_row.category, log_row.message,
                ",".join(log_row.signature_ids),
            ]
            if include_fields:
                for label in extra_cols:
                    row.append(log_row.value_for(label))
            w.writerow(row)
            n += 1
    return n


# ── JSON / JSONL writer ───────────────────────────────────────────────────────

def _write_json(
    conn: sqlite3.Connection,
    out: Path,
    where: str,
    params: list,
    include_fields: bool,
    *,
    has_kb: bool,
    jsonl: bool,
) -> int:
    n = 0
    with out.open("w", encoding="utf-8") as fp:
        if not jsonl:
            fp.write("[")
        first = True
        for log_row in _iter_logs(conn, where, params, has_kb=has_kb):
            obj = {
                "timestamp": log_row.timestamp_iso,
                "timestamp_unix_ns": log_row.timestamp_unix_ns,
                "event_order": log_row.event_order,
                "process": log_row.process,
                "pid": log_row.pid,
                "tid": log_row.tid,
                "log_level": log_row.log_level,
                "event_type": log_row.event_type,
                "subsystem": log_row.subsystem,
                "category": log_row.category,
                "message": log_row.message,
                "matched_signatures": list(log_row.signature_ids),
            }
            if include_fields:
                obj["extracted_values"] = log_row.values_dict()
            line = json.dumps(obj, ensure_ascii=False)
            if jsonl:
                fp.write(line); fp.write("\n")
            else:
                if not first:
                    fp.write(",\n  ")
                else:
                    fp.write("\n  ")
                    first = False
                fp.write(line)
            n += 1
        if not jsonl:
            fp.write("\n]\n")
    return n


# ── Streaming logs+annotations ────────────────────────────────────────────────

class _LogRow:
    """One log entry with its matched signatures and extracted values rolled up.

    The streaming join yields one row per (annotation × extracted value), so a
    single log spans several adjacent rows that are accumulated here: distinct
    signature ids, and distinct values per label (joined with "; " when a label
    legitimately holds several values across annotations).
    """

    __slots__ = (
        "log_id", "timestamp_unix_ns", "event_order",
        "process", "pid", "tid",
        "log_level", "event_type", "subsystem", "category", "message",
        "signature_ids", "_values_by_label",
    )

    def __init__(self, row: tuple) -> None:
        (self.log_id, self.timestamp_unix_ns, self.event_order,
         self.process, self.pid, self.tid,
         self.log_level, self.event_type, self.subsystem, self.category,
         self.message, _sig_id, _label, _value) = row
        self.signature_ids: list[str] = []
        self._values_by_label: dict[str, list[str]] = {}
        self.absorb(_sig_id, _label, _value)

    @property
    def timestamp_iso(self) -> str:
        """ISO 8601 (ns-precise) timestamp, formatted from the stored unix_ns.

        The ISO string is not persisted on ``logs`` (see schema.py); the export
        formats it on read so CSV/JSON keep a human-readable ``timestamp`` column.
        A failed resolution is stored as the sentinel ``unix_ns == 0``; emit an
        empty string for it rather than a misleading 1970-01-01 date.
        """
        if self.timestamp_unix_ns == 0:
            return ""
        return iso8601_from_unix_ns(self.timestamp_unix_ns)

    def absorb(self, sig_id: str | None, label: str | None, value: str | None) -> None:
        if sig_id and sig_id not in self.signature_ids:
            self.signature_ids.append(sig_id)
        if label is not None and value is not None:
            vals = self._values_by_label.setdefault(label, [])
            if value not in vals:
                vals.append(value)

    def value_for(self, label: str) -> str:
        """CSV cell for *label* — distinct values joined, or empty string."""
        vals = self._values_by_label.get(label)
        return "; ".join(vals) if vals else ""

    def values_dict(self) -> dict[str, str]:
        """JSON object of label → joined value (only labels present on this log)."""
        return {label: "; ".join(vals) for label, vals in self._values_by_label.items()}


def _iter_logs(
    conn: sqlite3.Connection,
    where: str,
    params: list,
    *,
    has_kb: bool,
) -> Iterable[_LogRow]:
    """Stream logs joined with annotations + extracted values, collapsing duplicates.

    With KB tables present the LEFT JOINs produce one row per
    (log × annotation × extracted value); we order by (timestamp, log_id) so all
    rows for a log land contiguously and are accumulated in Python.
    """
    if has_kb:
        sql = f"""
            SELECT
                l.id, l.timestamp_unix_ns, l.event_order,
                p.name, l.pid, l.tid,
                ll.name, et.name, s.name, c.name, l.message,
                kbs.signature_id, ev.label, ev.value
            FROM logs l
            LEFT JOIN processes  p   ON p.id = l.process_id
            LEFT JOIN subsystems s   ON s.id = l.subsystem_id
            LEFT JOIN categories c   ON c.id = l.category_id
            LEFT JOIN log_levels  ll ON ll.id = l.log_level_id
            LEFT JOIN event_types et ON et.id = l.event_type_id
            LEFT JOIN log_annotations la  ON la.log_id = l.id
            LEFT JOIN kb_signatures   kbs ON kbs.id = la.kb_signature_id
            LEFT JOIN extracted_values ev ON ev.log_annotation_id = la.id
            WHERE {where}
            ORDER BY l.timestamp_unix_ns ASC, l.id ASC, kbs.signature_id ASC
        """
    else:
        sql = f"""
            SELECT
                l.id, l.timestamp_unix_ns, l.event_order,
                p.name, l.pid, l.tid,
                ll.name, et.name, s.name, c.name, l.message,
                NULL, NULL, NULL
            FROM logs l
            LEFT JOIN processes  p   ON p.id = l.process_id
            LEFT JOIN subsystems s   ON s.id = l.subsystem_id
            LEFT JOIN categories c   ON c.id = l.category_id
            LEFT JOIN log_levels  ll ON ll.id = l.log_level_id
            LEFT JOIN event_types et ON et.id = l.event_type_id
            WHERE {where}
            ORDER BY l.timestamp_unix_ns ASC, l.id ASC
        """
    cur = conn.execute(sql, params)
    pending: _LogRow | None = None
    for row in cur:
        log_id = row[0]
        if pending is None:
            pending = _LogRow(row)
            continue
        if log_id == pending.log_id:
            # Trailing trio = (kbs.signature_id, ev.label, ev.value); they are the
            # last three SELECT columns (indices shift if the column list changes).
            pending.absorb(row[-3], row[-2], row[-1])
            continue
        yield pending
        pending = _LogRow(row)
    if pending is not None:
        yield pending


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_format(path: Path) -> str | None:
    suf = path.suffix.lower()
    if suf == ".csv":   return "csv"
    if suf == ".jsonl": return "jsonl"
    if suf == ".json":  return "json"
    return None


def _to_unix_ns(value: str) -> int:
    """Parse an ISO 8601 datetime to nanoseconds since epoch (UTC)."""
    # Strip a trailing Z that fromisoformat doesn't accept on older Pythons.
    v = value.rstrip("Z")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"cannot parse datetime {value!r}: {exc}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


