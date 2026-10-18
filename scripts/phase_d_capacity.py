"""File-backed, explicitly bounded capacity policy for Phase D artifacts."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from time import monotonic

MiB = 1024 * 1024


@dataclass(frozen=True)
class CapacityPolicy:
    max_archive_bytes: int
    max_entry_bytes: int
    max_expanded_bytes: int
    max_temp_disk_bytes: int
    max_buffer_bytes: int = MiB
    max_processing_seconds: int = 20 * 60
    max_concurrent_operations: int = 1
    max_open_archives: int = 1
    max_archive_entries: int = 6
    max_source_entries: int = 5000
    max_directory_bytes: int = 65536
    max_extraction_depth: int = 1

    def __post_init__(self):
        limits = (self.max_archive_bytes, self.max_entry_bytes, self.max_expanded_bytes,
                  self.max_temp_disk_bytes, self.max_buffer_bytes, self.max_processing_seconds,
                  self.max_concurrent_operations, self.max_open_archives,
                  self.max_archive_entries, self.max_source_entries, self.max_directory_bytes,
                  self.max_extraction_depth)
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError("Capacity limits must be positive integers")
        if self.max_buffer_bytes > MiB or self.max_archive_bytes > self.max_temp_disk_bytes:
            raise ValueError("Capacity policy exceeds its bounded buffer or disk budget")


DEFAULT_CAPACITY = CapacityPolicy(
    max_archive_bytes=256 * MiB,
    max_entry_bytes=256 * MiB,
    max_expanded_bytes=512 * MiB,
    max_temp_disk_bytes=2 * 256 * MiB + 512 * MiB,
)

# Benchmark-only profile. It is a module constant, never selected by workflow input,
# release metadata, environment variables, or the operational Publisher entry point.
TWO_X_STRESS_TEST_CAPACITY = CapacityPolicy(
    max_archive_bytes=768 * MiB,
    max_entry_bytes=512 * MiB,
    max_expanded_bytes=1024 * MiB,
    max_temp_disk_bytes=2 * 768 * MiB + 1024 * MiB,
)


@dataclass(frozen=True)
class ArtifactFile:
    path: Path
    size: int
    sha256: str

    def open(self):
        return self.path.open("rb")

    def verify(self, chunk_bytes=MiB):
        if not self.path.is_file() or self.path.stat().st_size != self.size:
            raise ValueError("Staged artifact size changed")
        digest = hashlib.sha256()
        with self.open() as source:
            while chunk := source.read(chunk_bytes):
                digest.update(chunk)
        if digest.hexdigest() != self.sha256:
            raise ValueError("Staged artifact digest changed")
        return self.size, self.sha256

    def read_bytes(self):
        """Convenience for small offline fixtures; production paths stream this file."""
        return self.path.read_bytes()


class _Sink:
    def __init__(self, workspace, name, max_bytes, kind):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name):
            raise ValueError("Unsafe temporary artifact name")
        if kind not in ("archive", "expanded", "staging"):
            raise ValueError("Unknown temporary artifact category")
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("Invalid per-file byte limit")
        self.workspace, self.max_bytes, self.kind = workspace, max_bytes, kind
        self.path = workspace.root / name
        self.stream = self.path.open("xb")
        self.size = 0
        self.digest = hashlib.sha256()
        self.closed = False

    def write(self, chunk):
        self.workspace.check_deadline()
        if not isinstance(chunk, bytes):
            raise TypeError("Artifact stream must yield bytes")
        if not chunk:
            return 0
        amount = len(chunk)
        if self.size + amount > self.max_bytes:
            raise ValueError("Artifact file size limit exceeded")
        if self.workspace.disk_bytes + amount > self.workspace.policy.max_temp_disk_bytes:
            raise ValueError("Temporary disk budget exceeded")
        if self.kind == "archive" and self.size + amount > self.workspace.policy.max_archive_bytes:
            raise ValueError("Downloaded archive exceeds size limit")
        if self.kind == "expanded" and self.workspace.expanded_bytes + amount > self.workspace.policy.max_expanded_bytes:
            raise ValueError("Actual decompression size limit exceeded")
        self.stream.write(chunk)
        self.digest.update(chunk)
        self.size += amount
        self.workspace.disk_bytes += amount
        if self.kind == "expanded":
            self.workspace.expanded_bytes += amount
        return amount

    def finish(self):
        if self.closed:
            raise ValueError("Artifact stream already closed")
        self.stream.flush()
        self.stream.close()
        self.closed = True
        if self.size == 0:
            self.path.unlink(missing_ok=True)
            self.workspace.sinks.discard(self)
            raise ValueError("Empty artifact is not permitted")
        if os.name != "nt":
            try:
                self.path.chmod(0o400)
            except OSError:
                pass
        artifact = ArtifactFile(self.path, self.size, self.digest.hexdigest())
        self.workspace.files[self.path] = artifact
        self.workspace.sinks.discard(self)
        return artifact

    def abort(self):
        if not self.closed:
            self.stream.close()
            self.closed = True
        if self.path.exists():
            size = self.path.stat().st_size
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            self.path.unlink()
            self.workspace.disk_bytes -= size
            if self.kind == "expanded":
                self.workspace.expanded_bytes -= size
        self.workspace.sinks.discard(self)


class ArtifactWorkspace:
    """One operation's private temp directory and aggregate resource accounting."""
    def __init__(self, policy=DEFAULT_CAPACITY, parent=None):
        if not isinstance(policy, CapacityPolicy):
            raise TypeError("An immutable capacity policy is required")
        self.policy = policy
        self._temporary = tempfile.TemporaryDirectory(prefix="phase-d-", dir=parent)
        self.root = Path(self._temporary.name)
        self.disk_bytes = 0
        self.expanded_bytes = 0
        self.started = monotonic()
        self.closed = False
        self.open_archives = 0
        self.files = {}
        self.sinks = set()
        self.archives = {}
        self.source_files = {}
        self.release_files = {}
        self.provenance = []

    def check_deadline(self):
        if self.closed:
            raise ValueError("Artifact workspace is closed")
        if monotonic() - self.started > self.policy.max_processing_seconds:
            raise TimeoutError("Artifact processing time limit exceeded")

    def sink(self, name, max_bytes, kind):
        self.check_deadline()
        sink = _Sink(self, name, max_bytes, kind)
        self.sinks.add(sink)
        return sink

    def write_bytes(self, name, data, max_bytes, kind):
        sink = self.sink(name, max_bytes, kind)
        try:
            for offset in range(0, len(data), self.policy.max_buffer_bytes):
                sink.write(data[offset:offset + self.policy.max_buffer_bytes])
            return sink.finish()
        except BaseException:
            sink.abort()
            raise

    def copy_stream(self, source, name, max_bytes, kind):
        sink = self.sink(name, max_bytes, kind)
        try:
            while True:
                self.check_deadline()
                chunk = source.read(self.policy.max_buffer_bytes)
                if not chunk:
                    break
                sink.write(chunk)
            return sink.finish()
        except BaseException:
            sink.abort()
            raise

    def download(self, call, route, name, max_bytes, kind="archive"):
        sink = self.sink(name, max_bytes, kind)
        try:
            result = call(route, raw=True, sink=sink)
            if isinstance(result, ArtifactFile):
                if result.path != sink.path:
                    sink.abort()
                return result
            if isinstance(result, bytes):
                for offset in range(0, len(result), self.policy.max_buffer_bytes):
                    sink.write(result[offset:offset + self.policy.max_buffer_bytes])
            elif result is not None:
                raise TypeError("Artifact download returned an unsupported value")
            return sink.finish()
        except BaseException:
            sink.abort()
            raise

    def open_archive(self):
        self.check_deadline()
        if self.open_archives + 1 > self.policy.max_open_archives:
            raise ValueError("Simultaneous archive limit exceeded")
        self.open_archives += 1

    def close_archive(self):
        if self.open_archives <= 0:
            raise ValueError("Archive accounting underflow")
        self.open_archives -= 1

    def close(self):
        if self.closed:
            return
        self.closed = True
        for sink in tuple(self.sinks):
            sink.abort()
        shutil.rmtree(self.root, ignore_errors=True)
        self._temporary.cleanup()

    def __enter__(self):
        self.check_deadline()
        return self

    def __exit__(self, *_):
        self.close()
