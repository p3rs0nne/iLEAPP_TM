# `forensic_aul` — API recommendations from a consumer (iLEAPP Surveillance module)

Context: the iLEAPP fork's `Surveillance.py` uses `forensic_aul` to parse a
sysdiagnose logarchive (or an FFS `diagnostics`+`uuidtext` pair) and then read a
**few specific event types** out of the result — local `BackupAgent2` backup
sessions and companion-link computer-presence events. The pattern is: *parse
once → `SELECT WHERE <something> → put rows in a table, almost untouched*.

Doing that today required (a) calling `run_extract`, then (b) opening the output
database with `sqlite3` and querying the **internal schema directly**
(`logs`, `subsystems`, `format_strs`, `case_metadata`). The README says that
schema is "internal implementation detail and may change", so every consumer that
reads events is coupled to something the library doesn't promise to keep stable.
The recommendations below are ordered by how much friction they remove.

What already works well, for balance: `run_extract`'s single entry point, the
auto-detection of logarchive / sysdiagnose / FFS / loose-dirs inputs, the
`{"diagnostics","uuidtext"}` mapping, and the `progress` callback are all good and
were enough to build a working integration in one file.

---

## R1 — A stable, in-memory **read API** for the parsed logs (highest value)

**Friction.** There is no public way to get rows out of the parsed database. The
only row-level outputs are `run_export` (writes a CSV/JSON/JSONL *file*, then you
re-read it) and the annotation/KB system (needs YAML signature files on disk). To
read "every `com.apple.rapport` message starting with `Bonjour unauth peer
found`" we wrote raw SQL against `logs` + `subsystems` + `format_strs`. If those
column names change, every consumer breaks silently.

**Recommendation.** Expose a small, documented, **stable** query function that
returns rows in memory (an iterator of `LogEntry`, which is already a public
dataclass), keyed on the fields people actually filter by:

```python
from forensic_aul import query_logs   # NEW, top-level

for entry in query_logs(
        db_path,
        subsystem="com.apple.rapport",          # exact or prefix
        message_prefix="Bonjour unauth peer ",  # matches the *composed* message
        format_str="%{public}s: %{public}s",    # the invariant template, when present
        time_from=..., time_to=...,
        limit=None):
    ...  # entry.timestamp, entry.subsystem, entry.message, entry.process, ...
```

This is the single change that would let a consumer stop touching the schema.
Even just **publishing a stable read VIEW** (e.g. `v_logs(timestamp, process,
subsystem, category, message, format_string, ...)` joining the lookup tables) and
promising to keep *that* stable would be enough — consumers could query the view
and ignore the normalised `*_id` columns.

Today `run_export` already has the right filter vocabulary in `ExportFilters`
(`process, subsystem, level, grep, signature, time_from, time_to`). The ask is
essentially **"the same filters, but yielding rows instead of writing a file."**

---

## R2 — Let consumers **skip source hashing** (the prepare phase)

**Friction.** `run_extract` always runs `prepare_source`, which calls
`hash_logarchive()` over the *entire* source (SHA-256 of content + every file) for
chain-of-custody. On the test fixture that is ~406 MB / ~1,356 files hashed on
**every run**, before any parsing starts. For an interactive/triage consumer
(iLEAPP) that does not need the forensic attestation, this is pure latency, and
there is no flag to turn it off.

**Recommendation.** Add an opt-out, e.g. `run_extract(..., hash_source=False)`
(or `integrity="off"`), threaded into `prepare_source(..., hash_source=False)`,
that skips `hash_logarchive` and leaves `content_sha256=None` / `file_hashes={}`.
Keep hashing **on by default** (forensic safety), but let a caller that values
speed over attestation skip it. The post-run `verify_unchanged()` re-check would
naturally no-op when no baseline hash was taken.

If a full SHA-256 of every file is considered too cheap to bother optimising, a
middle option is a **fingerprint-only** mode (size + mtime, or a sampled hash)
that detects gross tampering without reading every byte.

---

## R3 — Re-export the **progress** types and ready-made sinks

**Friction.** `progress=` takes a `ProgressSink`, but `ProgressSink`,
`ProgressEvent`, and the ready-made `logging_progress_sink` / `tty_bar_sink` live
in `forensic_aul.engine.utils.progress` and are **not** in `__all__`. A consumer
that wants to build or type a sink, or just reuse the logging sink, has to import
from an internal path the README warns against. (We worked around it by passing a
bare untyped lambda and hand-reading `event.overall` / `event.phase`.)

**Recommendation.** Re-export `ProgressSink`, `ProgressEvent`, and
`logging_progress_sink` (and `tty_bar_sink`) at the top level. Bonus: a tiny
adapter so a host with its own logger (iLEAPP's `logfunc`) can plug in without
constructing a `logging.Logger` — e.g. `callback_progress_sink(fn, every_percent=10)`.

---

## R4 — Make the `jobs > 1` **`__main__`-guard requirement** explicit (footgun)

**Friction.** With `jobs > 1`, extraction uses spawn-based multiprocessing
(`ProcessPoolExecutor`). When the calling code is **not** under an
`if __name__ == "__main__":` guard (very common for a library imported by a host —
e.g. a dynamically-loaded plugin, a notebook, a background worker), the spawned
workers re-import the caller and misbehave: in our first attempts the run exited
"successfully" having written **0 rows**, with no error. It took real digging to
trace this to the missing guard.

**Recommendation.** Either (a) document this prominently next to `jobs` in the
`run_extract` docstring/README ("`jobs>1` requires the entry point to be import-safe
/ under a `__main__` guard"), or (b) detect the unsafe condition and **degrade
gracefully** (fall back to `jobs=1` with a warning) instead of silently producing
an empty database. A silent empty result is the worst outcome.

---

## R5 — Reconsider the `fts=True` default

**Friction.** `fts` defaults to `True`, building an FTS5 full-text index over the
whole `logs.message` column (millions of rows). A consumer that queries by
`subsystem` / `format_str` / message-prefix (indexed columns) never needs it, and
it is a large, easily-missed cost. We had to know to pass `fts=False`.

**Recommendation.** Default `fts=False` (opt **in** to full-text), or at least
flag the cost loudly in the docstring. Most programmatic consumers filter on
structured columns, not free text.

---

## R6 — Document the **dynamic-message / NULL `format_str`** reality

**Friction.** The natural "match on the invariant format string" strategy (which
is the right one for ~97% of rows on our fixture) silently fails for the events we
most cared about: launchd lifecycle lines like `Successfully spawned
BackupAgent2[550] …` and `exited due to exit(0), ran for 14268ms` are **dynamic**
(`format_str_id IS NULL` — only the schema comment "NULL for dynamic" hints at
this), and companion-link lines use the generic `%{public}s` template (present but
useless for filtering). We only discovered this by querying the DB and reading the
schema source.

**Recommendation.** Document, for consumers, which message classes carry no usable
format string (dynamic / `%{public}s`) and therefore must be matched on the
composed `message`. Even better: expose a normalised **match key** (the format
string when specific, else the message with its embedded values masked) so a
consumer has one stable thing to `WHERE` on regardless of message class.

---

## R7 — A "parse once, reuse" convenience (minor)

**Friction.** Consumers commonly want to parse once and run many queries (and,
within one host run, share the DB across several features). We implemented the
"does the DB already exist? if so skip extraction" logic ourselves.

**Recommendation.** A thin helper such as
`open_or_extract(source, db_path, **opts) -> Path` that extracts only when
`db_path` is absent (and otherwise returns it) would standardise the pattern and
pair naturally with R1's read API.

---

## R8 — FFS directory discovery helper (minor)

**Friction.** For an FFS we had to locate `private/var/db/diagnostics` and
`private/var/db/uuidtext` ourselves before calling
`prepare_loose_dirs` / passing the mapping.

**Recommendation.** A helper like `find_loose_dirs(fs_root) -> {"diagnostics":
..., "uuidtext": ...} | None` (the inverse of what consumers hand-roll) would
remove a fiddly, easy-to-get-wrong step.

---

### Summary

The two changes that would most improve the consumer experience are **R1** (a
stable in-memory read API / view, so consumers stop coupling to the internal
schema) and **R2** (an option to skip source hashing for non-forensic / triage
use). **R3–R6** remove smaller footguns (progress exports, the `jobs>1` guard,
the FTS default, and the undocumented dynamic-message behaviour). **R7–R8** are
nice-to-have conveniences.
