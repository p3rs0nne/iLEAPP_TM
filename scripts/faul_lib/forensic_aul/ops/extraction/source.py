"""Input-source preparation for the extract pipeline.

Defines : the source-preparation layer that normalises any supported evidence
          container into a directory laid out as a ``.logarchive`` (the layout
          the parser already understands), plus the integrity hashes recorded
          for chain of custody.

          Three single-path source types are detected header-first, by magic
          bytes — never by extension alone:
            - LOGARCHIVE  — a ``.logarchive`` directory (used as-is, no copy).
            - SYSDIAGNOSE — a ``.tar.gz`` whose wrapper folder contains a
                            self-contained ``system_logs.logarchive/``.
            - FILESYSTEM  — a full-file-system ``.zip`` whose unified-log
                            material lives under (possibly a root folder such
                            as ``filesystem1/`` then) ``private/var/db/
                            diagnostics/`` and ``private/var/db/uuidtext/``.

          A fourth type is given explicitly (not detected) — two already-
          uncompressed folders passed as a mapping:
            - LOOSE_DIRS  — ``{"diagnostics": dir, "uuidtext": dir}`` — the same
                            two folders an FFS zip carries, but loose on disk.
                            Merged (by per-file symlink, no copy) into a single
                            logarchive root, identical in shape to the FFS case.

Used by : forensic_aul/extract.py (run_extract) — it prepares the source, parses
          ``logarchive_root``, and records the provenance fields on case_metadata.
Uses    : forensic_aul/engine/integrity.py (compute_sha256, hash_logarchive),
          and the Python standard library (tarfile, zipfile, tempfile, hashlib).
"""

from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import shutil
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath

from forensic_aul.engine.integrity import compute_sha256, hash_logarchive

log = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────────

# Sysdiagnose: the self-contained logarchive sits under a wrapper folder named
# after the tarball; we key off the well-known directory name, not the wrapper.
_LOGARCHIVE_MARKER = "system_logs.logarchive/"

# FFS: unified-log material lives under these two well-known paths, optionally
# beneath a root folder (e.g. "filesystem1/"). Both fold cleanly onto the
# logarchive root — diagnostics contributes Persist/Special/Signpost/HighVolume/
# timesync, uuidtext contributes the 2-char dirs + dsc/ — with no name clashes.
_DIAGNOSTICS_MARKER = "private/var/db/diagnostics/"
_UUIDTEXT_MARKER = "private/var/db/uuidtext/"

# LOOSE_DIRS: the two keys a mapping source must carry — the already-uncompressed
# equivalents of the FFS markers above (diagnostics/ holds the tracev3 material,
# uuidtext/ the format-string tables). Exposed so callers build the dict by name.
LOOSE_DIAGNOSTICS_KEY = "diagnostics"
LOOSE_UUIDTEXT_KEY = "uuidtext"

# Authoritative iOS-version source: SystemVersion.plist lives OUTSIDE the
# logarchive tree, so it is captured opportunistically during extraction (when
# present). Matched case-insensitively by path tail.
_SYSVERSION_FFS = "system/library/coreservices/systemversion.plist"  # full-file-system
_SYSVERSION_SD = "systemversion/systemversion.plist"                  # sysdiagnose logs/

# Window read from each end of an archive for the quick fingerprint. 64 KiB is
# enough to cover a zip's End-of-Central-Directory record plus a typical central
# directory, and a gzip header/trailer.
_FINGERPRINT_WINDOW = 64 * 1024

# Placeholder stored in case_metadata.logarchive_path when the logarchive was
# extracted into an auto-cleaned temp dir: the real path is gone after the run
# and would be a misleading dangling reference. WHY: a forensic record must not
# point at a path that no longer exists; --work-dir records the real path.
TEMP_DIR_PLACEHOLDER = "(temporary directory — not retained)"


class SourceType(Enum):
    """Recognised evidence container types."""

    LOGARCHIVE = "logarchive"
    SYSDIAGNOSE = "sysdiagnose"
    FILESYSTEM = "filesystem"
    LOOSE_DIRS = "loose_dirs"


@dataclass
class PreparedSource:
    """A source normalised to a logarchive-laid-out directory, ready to parse.

    Acts as a context manager: on exit it removes any temp dir it created. For a
    LOGARCHIVE source nothing is copied and there is nothing to clean up.
    """

    source_type: SourceType
    original_path: Path           # the evidence the analyst supplied
    logarchive_root: Path         # directory laid out as a logarchive
    content_sha256: str           # hash_logarchive() fingerprint of the material
    file_hashes: dict[str, str]   # relative-path → sha256, for source_files
    # Quick tamper-evident fingerprint of the archive, captured before extraction;
    # None for a LOGARCHIVE dir (there is no single archive file to attest).
    archive_fingerprint: str | None = None
    # Authoritative iOS version from SystemVersion.plist (FFS / sysdiagnose only);
    # None for a bare logarchive dir, where extract falls back to the build code.
    ios_product_version: str | None = None
    # Logarchive Info.plist ArchiveIdentifier (provenance / documentation), if any.
    archive_identifier: str | None = None
    # Internal: the temp dir backing logarchive_root, if extraction was temporary.
    _tempdir: tempfile.TemporaryDirectory | None = field(default=None, repr=False)

    @property
    def is_temporary(self) -> bool:
        """True when logarchive_root is an auto-cleaned temp dir (no --work-dir)."""
        return self._tempdir is not None

    @property
    def recorded_logarchive_path(self) -> str:
        """Value to store in case_metadata.logarchive_path (placeholder if temp)."""
        if self.is_temporary:
            return TEMP_DIR_PLACEHOLDER
        return str(self.logarchive_root)

    def verify_unchanged(self) -> bool:
        """Re-check the archive fingerprint — the 'after' half of the attestation.

        Returns True when the archive is byte-identical to its pre-extraction
        snapshot (or when there is no archive, i.e. a LOGARCHIVE dir). A False
        result means the evidence changed underneath us during the run, which the
        caller must surface in the forensic log.
        """
        if self.archive_fingerprint is None:
            return True
        return _quick_fingerprint(self.original_path) == self.archive_fingerprint

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None

    def __enter__(self) -> "PreparedSource":
        return self

    def __exit__(self, *_exc: object) -> bool:
        self.cleanup()
        return False


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_source_type(path: Path) -> SourceType:
    """Classify *path* as one of the supported sources.

    Header-first: a directory is a logarchive; a file is classified by its magic
    bytes (gzip ``1f 8b`` → sysdiagnose, zip ``PK\\x03\\x04`` → FFS). The file
    extension is never trusted on its own.

    Raises:
        ValueError: the path does not exist or is an unrecognised container.
    """
    if path.is_dir():
        return SourceType.LOGARCHIVE
    if not path.is_file():
        raise ValueError(f"Source does not exist or is not a file/directory: {path}")

    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic[:2] == b"\x1f\x8b":
        return SourceType.SYSDIAGNOSE
    if magic[:4] == b"PK\x03\x04":
        return SourceType.FILESYSTEM
    raise ValueError(
        f"Unrecognised source: {path} — expected a .logarchive directory, "
        f"a sysdiagnose .tar.gz, or a full-file-system .zip."
    )


# ── Quick archive fingerprint ──────────────────────────────────────────────────

def _quick_fingerprint(path: Path) -> str:
    """Cheap tamper-evident fingerprint: ``sha256(head ‖ size ‖ tail)``.

    HOW: hash the first 64 KiB, then the decimal file size, then the last 64 KiB
    (skipped when the file fits in the head window, so bytes are never counted
    twice). WHY this shape: it is cheap enough to recompute before *and* after a
    long run, yet a zip's central directory lives in the tail and the embedded
    size catches truncation — so realistic modifications are detected without
    re-reading a multi-gigabyte archive end to end.
    """
    size = path.stat().st_size
    h = hashlib.sha256()
    with path.open("rb") as fh:
        head = fh.read(_FINGERPRINT_WINDOW)
        h.update(head)
        h.update(str(size).encode("ascii"))
        if size > _FINGERPRINT_WINDOW:
            tail_start = max(size - _FINGERPRINT_WINDOW, len(head))
            fh.seek(tail_start)
            h.update(fh.read(_FINGERPRINT_WINDOW))
    return h.hexdigest()


# ── FFS path mapping (pure) ─────────────────────────────────────────────────────

def _ffs_match(name: str) -> tuple[str, PurePosixPath] | None:
    """Classify one FFS zip entry path.

    Returns ``(root_prefix, relpath)`` when *name* is a unified-log file under a
    diagnostics/ or uuidtext/ tree — where ``root_prefix`` is whatever precedes
    the marker (e.g. ``"filesystem1/"`` or ``""``) and ``relpath`` is the path
    relative to the logarchive root. Returns None for unrelated entries and for
    directory entries (paths ending in ``/``).
    """
    norm = name.replace("\\", "/")
    for marker in (_DIAGNOSTICS_MARKER, _UUIDTEXT_MARKER):
        idx = norm.find(marker)
        # Require the marker at the start or on a path boundary, so a file merely
        # *named* like the marker cannot be mistaken for the real directory.
        if idx != -1 and (idx == 0 or norm[idx - 1] == "/"):
            rest = norm[idx + len(marker):]
            if rest and not rest.endswith("/"):
                return norm[:idx], PurePosixPath(rest)
    return None


def _ffs_target_relpath(name: str) -> PurePosixPath | None:
    """Logarchive-relative target path for an FFS entry, or None to skip it."""
    matched = _ffs_match(name)
    return matched[1] if matched else None


# ── Safe extraction helpers ─────────────────────────────────────────────────────

def _safe_target(root: Path, rel: PurePosixPath) -> Path:
    """Resolve *rel* under *root*, refusing paths that escape it.

    WHY: archives are untrusted forensic input; a crafted ``../`` entry (zip-slip
    / tar-slip) could otherwise write outside the work dir.
    """
    root_resolved = root.resolve()
    dest = (root_resolved / rel).resolve()
    if not dest.is_relative_to(root_resolved):
        raise ValueError(f"Unsafe archive entry escapes work root: {rel}")
    return dest


def _make_work_root(name: str, work_dir: Path | None) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    """Return (root, tempdir-handle). With *work_dir* the root is kept; else temp.

    *name* is the stem of the kept ``<name>.logarchive`` directory — derived from
    the evidence so a retained --work-dir is self-describing.
    """
    if work_dir is not None:
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        root = work_dir / f"{name}.logarchive"
        root.mkdir(parents=True, exist_ok=True)
        return root, None
    tmp = tempfile.TemporaryDirectory(prefix="faul_source_")
    return Path(tmp.name), tmp


def _mirror_tree(src_dir: Path, dest_root: Path) -> tuple[int, int]:
    """Recreate *src_dir*'s tree under *dest_root*, hard-linking each regular file.

    Returns ``(files, copied)`` — the total files materialised and how many of them
    had to fall back to a byte copy. WHY hard links (not symlinks, not a copy):
      - zero-copy — a hard link is a second name for the same on-disk data, so
        multi-gigabyte ``tracev3`` files are not duplicated;
      - indistinguishable from a regular file — unlike a symlink, the link reports
        ``is_symlink() == False`` and ``is_file() == True``, so the forensic hasher
        (which deliberately skips symlinks) still hashes it and ``source_files`` is
        populated, and a later ``rglob`` (whose follow-symlinked-*directory*
        behaviour differs across Python 3.11–3.14) is never in play.
    The originals are only ever read. Hard links are unavailable on some
    filesystems (exFAT, certain network shares) and never span volumes, so when
    ``os.link`` fails the file is **copied** instead — same result, just more disk
    and time. If the copy also fails the error is re-raised with the path and the
    reason so the caller can surface a clear message. Source symlinks are skipped —
    a logarchive holds only regular files, and following one could pull in data
    from outside the evidence.
    """
    files = copied = 0
    src_dir = src_dir.resolve()
    # followlinks=False: never descend a symlinked directory in the source tree.
    for dirpath, _dirnames, filenames in os.walk(src_dir):
        rel_dir = Path(dirpath).relative_to(src_dir)
        for filename in filenames:
            src_file = Path(dirpath) / filename
            if src_file.is_symlink():
                continue
            dest = dest_root / rel_dir / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(src_file, dest)
            except OSError:
                # No hard-link support / cross-volume → copy the bytes instead.
                try:
                    shutil.copyfile(src_file, dest)
                except OSError as exc:
                    raise OSError(
                        f"Could not materialise {src_file} into the work dir "
                        f"{dest_root} — hard link and copy both failed: {exc}"
                    ) from exc
                copied += 1
            files += 1
    return files, copied


# ── Per-type extraction ─────────────────────────────────────────────────────────

# ── iOS-version / Info.plist helpers (stdlib plistlib, no dependencies) ──────────

def _product_version(data: bytes) -> str | None:
    """Return ``ProductVersion`` (e.g. "17.5.1") from a SystemVersion.plist blob."""
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 — a bad/foreign plist must not fail extraction
        log.debug("SystemVersion.plist parse failed: %s", exc)
        return None
    value = parsed.get("ProductVersion") if isinstance(parsed, dict) else None
    return str(value) if value else None


def _read_info_plist(root: Path) -> dict | None:
    """Parse ``<root>/Info.plist`` (logarchive metadata), or None if absent/bad."""
    info_path = root / "Info.plist"
    if not info_path.is_file():
        return None
    try:
        parsed = plistlib.loads(info_path.read_bytes())
        return parsed if isinstance(parsed, dict) else None
    except Exception as exc:  # noqa: BLE001
        log.debug("Info.plist parse failed: %s", exc)
        return None


def _extract_sysdiagnose(archive: Path, root: Path) -> str | None:
    """Extract ``system_logs.logarchive/`` from a sysdiagnose tarball into *root*.

    The marker prefix (wrapper folder + ``system_logs.logarchive/``) is stripped
    so *root* itself becomes the logarchive. Returns the iOS ``ProductVersion`` if
    the tarball carries a ``SystemVersion.plist`` (captured during the same pass).
    """
    n = 0
    product_version: str | None = None
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            norm = member.name.replace("\\", "/")
            # Authoritative iOS version (outside the logarchive tree).
            if (
                product_version is None
                and member.isfile()
                and norm.lower().endswith(_SYSVERSION_SD)
            ):
                src = tf.extractfile(member)
                if src is not None:
                    with src:
                        product_version = _product_version(src.read())
                continue
            idx = norm.find(_LOGARCHIVE_MARKER)
            if idx == -1:
                continue
            # Skip links: only regular files belong in a logarchive, and links
            # could point outside the work root.
            if member.issym() or member.islnk():
                continue
            rest = norm[idx + len(_LOGARCHIVE_MARKER):]
            if not rest or rest.endswith("/") or not member.isfile():
                continue
            dest = _safe_target(root, PurePosixPath(rest))
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
    if n == 0:
        raise ValueError(
            f"Sysdiagnose archive has no {_LOGARCHIVE_MARKER} content: {archive}"
        )
    log.info(f"Sysdiagnose: extracted {n} logarchive file(s)")
    return product_version


def _extract_ffs(archive: Path, root: Path) -> str | None:
    """Extract diagnostics/ + uuidtext/ from an FFS zip into a logarchive *root*.

    Returns the iOS ``ProductVersion`` if the zip carries a ``SystemVersion.plist``
    under ``System/Library/CoreServices/`` (read directly — zip random access).
    """
    product_version: str | None = None
    with zipfile.ZipFile(archive) as zf:
        matched: list[tuple[zipfile.ZipInfo, str, PurePosixPath]] = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Authoritative iOS version (outside diagnostics/uuidtext).
            if product_version is None and info.filename.replace("\\", "/").lower().endswith(_SYSVERSION_FFS):
                product_version = _product_version(zf.read(info))
                continue
            # Skip symlink entries (unix mode in the high 16 bits of external_attr).
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                continue
            m = _ffs_match(info.filename)
            if m is None:
                continue
            prefix, rel = m
            matched.append((info, prefix, rel))

        if not matched:
            raise ValueError(
                f"FFS zip has no {_DIAGNOSTICS_MARKER} / {_UUIDTEXT_MARKER} content: {archive}"
            )

        # Pick the root folder that actually holds diagnostics; if several do
        # (multiple filesystemN roots), warn and use the first deterministically.
        diag_prefixes = sorted(
            {p for (info, p, _rel) in matched if _DIAGNOSTICS_MARKER in info.filename.replace("\\", "/")}
        )
        chosen = diag_prefixes[0] if diag_prefixes else sorted({p for (_i, p, _r) in matched})[0]
        if len(diag_prefixes) > 1:
            log.warning(f'FFS: multiple root folders contain diagnostics {diag_prefixes} — using {chosen or "(archive root)"!r}')

        n = 0
        for info, prefix, rel in matched:
            if prefix != chosen:
                continue
            dest = _safe_target(root, rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
    log.info(f'FFS: extracted {n} file(s) from root {chosen or "(archive root)"!r}')
    return product_version


# ── Public entry point ──────────────────────────────────────────────────────────

def prepare_source(
    source: Path | str | Mapping[str, Path | str],
    *,
    work_dir: Path | None = None,
) -> PreparedSource:
    """Normalise *source* into a logarchive-laid-out directory ready for parsing.

    *source* is either a single path (auto-detected — a logarchive directory, a
    sysdiagnose tarball, or an FFS zip) or a mapping of two already-uncompressed
    folders, ``{"diagnostics": dir, "uuidtext": dir}`` (see
    :data:`LOOSE_DIAGNOSTICS_KEY` / :data:`LOOSE_UUIDTEXT_KEY`), which is routed to
    :func:`prepare_loose_dirs`.

    For a logarchive directory the directory is used in place (no copy). For a
    sysdiagnose tarball or an FFS zip the unified-log material is extracted into
    *work_dir* (kept) or an auto-cleaned temp dir, and a quick tamper-evident
    fingerprint of the archive is captured before extraction.

    Raises:
        ValueError: the source is unrecognised, lacks the expected content, or is
            a mapping missing the required keys.
    """
    if isinstance(source, Mapping):
        try:
            diagnostics = source[LOOSE_DIAGNOSTICS_KEY]
            uuidtext = source[LOOSE_UUIDTEXT_KEY]
        except KeyError as exc:
            raise ValueError(
                f"Loose-dirs source mapping needs keys {LOOSE_DIAGNOSTICS_KEY!r} "
                f"and {LOOSE_UUIDTEXT_KEY!r}; got {sorted(source)}"
            ) from exc
        return prepare_loose_dirs(Path(diagnostics), Path(uuidtext), work_dir=work_dir)

    path = Path(source)
    source_type = detect_source_type(path)

    if source_type is SourceType.LOGARCHIVE:
        content_sha256, file_hashes = hash_logarchive(path)
        info = _read_info_plist(path)
        return PreparedSource(
            source_type=source_type,
            original_path=path,
            logarchive_root=path,
            content_sha256=content_sha256,
            file_hashes=file_hashes,
            archive_fingerprint=None,
            ios_product_version=None,   # a bare logarchive carries only the build code
            archive_identifier=_archive_identifier(info),
            _tempdir=None,
        )

    # Archive sources: snapshot, extract, then hash the extracted material.
    archive_fingerprint = _quick_fingerprint(path)
    root, tmp = _make_work_root(path.stem, work_dir)
    try:
        if source_type is SourceType.SYSDIAGNOSE:
            product_version = _extract_sysdiagnose(path, root)
        else:  # FILESYSTEM — detect_source_type only returns these three
            product_version = _extract_ffs(path, root)
        content_sha256, file_hashes = hash_logarchive(root)
    except BaseException:
        # Don't leak a temp dir if extraction/hashing fails partway.
        if tmp is not None:
            tmp.cleanup()
        raise

    info = _read_info_plist(root)  # present for sysdiagnose's logarchive; absent for FFS
    if product_version:
        log.info(f"iOS version (SystemVersion.plist) : {product_version}")
    return PreparedSource(
        source_type=source_type,
        original_path=path,
        logarchive_root=root,
        content_sha256=content_sha256,
        file_hashes=file_hashes,
        archive_fingerprint=archive_fingerprint,
        ios_product_version=product_version,
        archive_identifier=_archive_identifier(info),
        _tempdir=tmp,
    )


def prepare_loose_dirs(
    diagnostics: Path,
    uuidtext: Path,
    *,
    work_dir: Path | None = None,
) -> PreparedSource:
    """Normalise two already-uncompressed folders into a logarchive layout.

    *diagnostics* is the on-device ``private/var/db/diagnostics/`` folder
    (Persist/Special/Signpost/HighVolume/ + timesync) and *uuidtext* is
    ``private/var/db/uuidtext/`` (the 2-char dirs + dsc/) — the same two folders an
    FFS zip carries, but loose on disk. Their contents are merged (by hard link
    where possible — zero-copy — falling back to a byte **copy** on filesystems
    that do not support hard links, e.g. exFAT or some network shares, or when the
    work dir is on a different volume; see :func:`_mirror_tree`) into one logarchive
    root in *work_dir* (kept) or an auto-cleaned temp dir, identical in shape to the
    FFS result. The originals are only ever read.

    There is no single archive to attest, so ``archive_fingerprint`` is None (as
    for a bare logarchive dir); ``content_sha256`` / ``file_hashes`` are computed
    over the merged root for chain of custody. ``original_path`` records the
    *diagnostics* folder as the representative source.

    Raises:
        ValueError: either path is not a directory, or together they hold no files.
    """
    diagnostics = Path(diagnostics)
    uuidtext = Path(uuidtext)
    for label, d in ((LOOSE_DIAGNOSTICS_KEY, diagnostics), (LOOSE_UUIDTEXT_KEY, uuidtext)):
        if not d.is_dir():
            raise ValueError(f"Loose-dirs {label} source is not a directory: {d}")

    root, tmp = _make_work_root("EXTRACTION_LOOSE", work_dir)
    try:
        files_d, copied_d = _mirror_tree(diagnostics, root)
        files_u, copied_u = _mirror_tree(uuidtext, root)
        n, copied = files_d + files_u, copied_d + copied_u
        if n == 0:
            raise ValueError(
                f"Loose-dirs source has no files: {diagnostics} / {uuidtext}"
            )
        if copied:
            # Hard links could not be used (the work dir is on a filesystem that
            # does not support them — exFAT / some network shares — or on a
            # different volume from the source). We fell back to copying, which is
            # correct but uses extra disk and time.
            log.warning(f"Loose dirs: hard links unavailable — copied {copied} of {n} file(s) into the work root instead (extra disk used; result is identical). To enable zero-copy, point --work-dir at the same filesystem as the source folders.")
        else:
            log.info(f"Loose dirs: hard-linked {n} file(s) into a logarchive root (zero-copy)")
        content_sha256, file_hashes = hash_logarchive(root)
    except BaseException:
        # Don't leak a temp dir if mirroring/hashing fails partway.
        if tmp is not None:
            tmp.cleanup()
        raise

    info = _read_info_plist(root)  # normally absent for loose dirs; harmless if present
    return PreparedSource(
        source_type=SourceType.LOOSE_DIRS,
        original_path=diagnostics,
        logarchive_root=root,
        content_sha256=content_sha256,
        file_hashes=file_hashes,
        archive_fingerprint=None,
        ios_product_version=None,   # SystemVersion.plist lives outside these two folders
        archive_identifier=_archive_identifier(info),
        _tempdir=tmp,
    )


def _archive_identifier(info: dict | None) -> str | None:
    """Pull the logarchive ArchiveIdentifier from a parsed Info.plist (provenance)."""
    if not info:
        return None
    value = info.get("ArchiveIdentifier")
    return str(value) if value else None
