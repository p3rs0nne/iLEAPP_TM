"""Timesync anchor pre-insertion — enables DB-free worker parsing.

Defines : _preinsert_timesync_anchors
Used by : forensic_aul.ops.extraction.extract (_run_parse)
Uses    : forensic_aul.engine.database.writer (BatchWriter),
          forensic_aul.engine.models (TimesyncAnchor, TimesyncBoot)
"""

from __future__ import annotations

import logging

from forensic_aul.engine.database.writer import BatchWriter
from forensic_aul.engine.models import TimesyncAnchor, TimesyncBoot

log = logging.getLogger(__name__)


def _preinsert_timesync_anchors(
    writer: BatchWriter,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid_to_timesync_file_id: dict[str, int],
) -> dict[tuple[int, int], int]:
    """Insert every anchor ``_select_anchor`` could pick; return (file_id, offset)→id.

    For each boot the selectable anchors are exactly: the boot record itself
    (file_offset = boot.file_offset, kernel_time = 0, walltime = boot_time) and
    one per timesync record (its own offset / kernel_time / walltime). Pre-inserting
    them lets parser workers resolve ``timesync_anchor_id`` with a pure dict lookup
    keyed by the same ``(timesync_file_id, file_offset)`` identity the writer dedups
    on — so a worker never touches the DB. Anchors never referenced by an entry are
    harmless extra rows. The timebase (1/1 Intel, 125/3 Apple Silicon) mirrors
    ``forensic_aul/engine/utils/time.py``.
    """
    anchor_id_map: dict[tuple[int, int], int] = {}
    for boot_uuid, boot in timesync_data.items():
        # Each anchor carries its own source-file id (boot header / record), so
        # a boot UUID spanning two files inserts and resolves each anchor against
        # the file it actually came from. The per-boot map is only a coarse
        # fallback for boots with no registered file at all.
        boot_file_id = boot.timesync_file_id or boot_uuid_to_timesync_file_id.get(boot_uuid)
        if boot_file_id is None:
            continue
        if boot.timebase_numerator == 125 and boot.timebase_denominator == 3:
            tb_num, tb_den = 125, 3
        else:
            tb_num, tb_den = 1, 1

        anchors = [
            TimesyncAnchor(
                boot_uuid=boot.boot_uuid,
                file_offset=boot.file_offset,
                kernel_continuous_time=0,
                walltime_unix_ns=boot.boot_time,
                timebase_numerator=tb_num,
                timebase_denominator=tb_den,
                timezone_offset_mins=boot.timezone_offset_mins,
                timesync_file_id=boot_file_id,
            )
        ]
        for rec in boot.timesync:
            anchors.append(
                TimesyncAnchor(
                    boot_uuid=boot.boot_uuid,
                    file_offset=rec.file_offset,
                    kernel_continuous_time=rec.kernel_time,
                    walltime_unix_ns=rec.walltime,
                    timebase_numerator=tb_num,
                    timebase_denominator=tb_den,
                    timezone_offset_mins=rec.timezone,
                    timesync_file_id=rec.timesync_file_id or boot_file_id,
                )
            )

        for anchor in anchors:
            anchor_id = writer.get_or_insert_timesync_anchor(anchor, anchor.timesync_file_id)
            anchor_id_map[(anchor.timesync_file_id, anchor.file_offset)] = anchor_id
    return anchor_id_map
