"""Storage pruning and disk-protection policy for live ECG output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Callable, Iterable, List, Optional, Set

from oad_parser.config import LiveParserConfig


NowFn = Callable[[], datetime]
DiskUsageFn = Callable[[str], object]


@dataclass(frozen=True)
class ClosedOutputFile:
    """Closed rotated output file eligible for live-output pruning."""

    path: str
    size_bytes: int
    modified_time_utc: datetime


@dataclass(frozen=True)
class StorageProtectionResult:
    """Result of applying pruning and disk-protection policy."""

    disk_usage_percent: float
    files_pruned: int
    bytes_pruned: int
    writer_blocked: bool
    critical: bool
    pruned_paths: List[str]
    protected_paths: List[str]


class LiveStoragePolicy:
    """Apply age and disk high-water pruning for closed live output files."""

    def __init__(
        self,
        *,
        active_output_path: str,
        audit_path: str = "/nsm/ecg/ecg-audit.jsonl",
        status_path: str = "/nsm/ecg/ecg-status.json",
        prune_after_seconds: int = 43200,
        disk_high_water_percent: int = 75,
        disk_critical_percent: int = 95,
        now_fn: Optional[NowFn] = None,
        disk_usage_fn: Optional[DiskUsageFn] = None,
    ) -> None:
        if prune_after_seconds < 0:
            raise ValueError("prune_after_seconds must be >= 0")
        if disk_high_water_percent < 0 or disk_high_water_percent > 100:
            raise ValueError("disk_high_water_percent must be between 0 and 100")
        if disk_critical_percent < 0 or disk_critical_percent > 100:
            raise ValueError("disk_critical_percent must be between 0 and 100")
        if disk_critical_percent <= disk_high_water_percent:
            raise ValueError("disk_critical_percent must be greater than disk_high_water_percent")

        self.active_output_path = Path(active_output_path)
        self.audit_path = Path(audit_path)
        self.status_path = Path(status_path)
        self.prune_after_seconds = int(prune_after_seconds)
        self.disk_high_water_percent = int(disk_high_water_percent)
        self.disk_critical_percent = int(disk_critical_percent)
        self._now_fn = now_fn if now_fn is not None else _utc_now
        self._disk_usage_fn = disk_usage_fn if disk_usage_fn is not None else shutil.disk_usage

    @classmethod
    def from_config(
        cls,
        config: LiveParserConfig,
        *,
        now_fn: Optional[NowFn] = None,
        disk_usage_fn: Optional[DiskUsageFn] = None,
    ) -> "LiveStoragePolicy":
        return cls(
            active_output_path=config.output_json_file,
            prune_after_seconds=config.prune_after_seconds,
            disk_high_water_percent=config.disk_high_water_percent,
            disk_critical_percent=config.disk_critical_percent,
            now_fn=now_fn,
            disk_usage_fn=disk_usage_fn,
        )

    def closed_output_files(self) -> List[ClosedOutputFile]:
        output_dir = self.active_output_path.parent
        if not output_dir.exists():
            return []

        protected = self._protected_paths()
        files = []
        for path in output_dir.iterdir():
            if not path.is_file():
                continue
            if path.resolve() in protected:
                continue
            if not self._is_closed_output_file(path):
                continue
            stat = path.stat()
            files.append(
                ClosedOutputFile(
                    path=str(path),
                    size_bytes=stat.st_size,
                    modified_time_utc=datetime.fromtimestamp(
                        stat.st_mtime,
                        timezone.utc,
                    ),
                )
            )

        return sorted(files, key=lambda item: item.modified_time_utc)

    def apply(self) -> StorageProtectionResult:
        pruned_paths: List[str] = []
        bytes_pruned = 0

        age_pruned_paths, age_pruned_bytes = self._prune_by_age()
        pruned_paths.extend(age_pruned_paths)
        bytes_pruned += age_pruned_bytes

        disk_percent = self._disk_usage_percent()
        if disk_percent >= self.disk_high_water_percent:
            high_pruned_paths, high_pruned_bytes = self._prune_for_high_water()
            pruned_paths.extend(high_pruned_paths)
            bytes_pruned += high_pruned_bytes
            disk_percent = self._disk_usage_percent()

        writer_blocked = disk_percent >= self.disk_high_water_percent
        critical = disk_percent >= self.disk_critical_percent

        return StorageProtectionResult(
            disk_usage_percent=disk_percent,
            files_pruned=len(pruned_paths),
            bytes_pruned=bytes_pruned,
            writer_blocked=writer_blocked,
            critical=critical,
            pruned_paths=pruned_paths,
            protected_paths=[str(path) for path in sorted(self._protected_paths())],
        )

    def _prune_by_age(self) -> tuple:
        if self.prune_after_seconds == 0:
            cutoff_age = 0
        else:
            cutoff_age = self.prune_after_seconds

        now = self._now_fn()
        candidates = []
        for item in self.closed_output_files():
            age = (now - item.modified_time_utc).total_seconds()
            if age > cutoff_age:
                candidates.append(Path(item.path))

        return _delete_files(candidates)

    def _prune_for_high_water(self) -> tuple:
        deleted_paths: List[str] = []
        deleted_bytes = 0

        for item in self.closed_output_files():
            if self._disk_usage_percent() < self.disk_high_water_percent:
                break
            paths, size = _delete_files([Path(item.path)])
            deleted_paths.extend(paths)
            deleted_bytes += size

        return deleted_paths, deleted_bytes

    def _is_closed_output_file(self, path: Path) -> bool:
        base = self.active_output_path.name
        if base.endswith(".json"):
            prefix = base[:-5] + "-"
        else:
            prefix = self.active_output_path.stem + "-"
        return path.name.startswith(prefix) and path.name.endswith(".jsonl")

    def _protected_paths(self) -> Set[Path]:
        protected = {
            self.active_output_path,
            self.audit_path,
            self.status_path,
        }
        return {path.resolve() for path in protected}

    def _disk_usage_percent(self) -> float:
        usage = self._disk_usage_fn(str(self.active_output_path.parent))
        total = float(getattr(usage, "total"))
        used = float(getattr(usage, "used"))
        if total <= 0:
            return 100.0
        return (used / total) * 100.0


def _delete_files(paths: Iterable[Path]) -> tuple:
    deleted_paths: List[str] = []
    deleted_bytes = 0

    for path in paths:
        try:
            stat = path.stat()
            path.unlink()
            deleted_paths.append(str(path))
            deleted_bytes += stat.st_size
        except FileNotFoundError:
            continue

    return deleted_paths, deleted_bytes


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
