"""forensic_aul — Forensic Apple Unified Log parser (iOS/macOS).

Defines : the public API of the installable core library. Other code (the CLI in
          launcher/, the GUI in gui/, or third-party callers) imports the
          operations from here, e.g. ``from forensic_aul import run_extract``.
Used by : launcher/* (CLI), gui/* (GUI controllers), and external consumers.
Uses    : the package's own submodules (extraction, annotation, identify, export,
          acquisition, database, models). Re-exported here so callers depend on a
          stable surface rather than internal module paths.
"""

from __future__ import annotations

__version__ = "0.1.0"

# ── Public API ────────────────────────────────────────────────────────────────
# Core pipeline
from forensic_aul.ops.extraction.extract import run_extract

# Annotation engine (load a knowledge base + annotate an extracted database)
from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.annotation.matcher import annotate_connection, annotate_database

# Action attribution (baseline vs action diff)
from forensic_aul.ops.identify.diff import run_diff

# Filtered export to CSV / JSON / JSONL (knowledge-base aware)
from forensic_aul.ops.export.exporter import ExportFilters, run_export

# Read-only analysis helpers (summary view + chain-of-custody verification)
from forensic_aul.ops.summary.summary import Summary, summarise
from forensic_aul.ops.verify.verify import VerifyResult, verify_database

# Device acquisition (collect a .logarchive over USB; optional pymobiledevice3)
from forensic_aul.ops.acquisition.acquire import (
    AcquisitionAborted,
    AcquisitionError,
    acquire,
)
from forensic_aul.ops.acquisition.device import DeviceInfo

# Forensic hashing / chain of custody
from forensic_aul.engine.integrity import compute_sha256, hash_logarchive

# Input-source preparation (logarchive dir / sysdiagnose .tar.gz / FFS .zip)
from forensic_aul.ops.extraction.source import (
    PreparedSource,
    SourceType,
    prepare_loose_dirs,
    prepare_source,
)

# Database schema helpers (for callers that build / inspect the SQLite store)
from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import apply_pragmas, init_schema

# Core row model (useful for callers that type-hint or post-process log rows)
from forensic_aul.engine.models import LogEntry

# Return-value containers for the top-level operations
from forensic_aul.outcomes import (
    AcquireResult,
    AnnotateResult,
    DiffResult,
    ExportResult,
    ExtractResult,
)

__all__ = [
    "__version__",
    "run_extract",
    "load_kb",
    "KnowledgeBaseError",
    "annotate_database",
    "annotate_connection",
    "run_diff",
    "run_export",
    "ExportFilters",
    "summarise",
    "Summary",
    "verify_database",
    "VerifyResult",
    "compute_sha256",
    "hash_logarchive",
    "prepare_source",
    "prepare_loose_dirs",
    "PreparedSource",
    "SourceType",
    "init_schema",
    "apply_pragmas",
    "assign_ordering",
    "LogEntry",
    "ExtractResult",
    "DiffResult",
    "ExportResult",
    "AnnotateResult",
    "acquire",
    "AcquireResult",
    "AcquisitionError",
    "AcquisitionAborted",
    "DeviceInfo",
]
