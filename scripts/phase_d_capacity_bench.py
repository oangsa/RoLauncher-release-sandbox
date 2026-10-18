"""Local-only Phase D capacity benchmark; never calls GitHub or Publisher."""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

import phase_d_fixtures as fixtures
import release_promotion as promotion
from phase_d_capacity import ArtifactWorkspace, DEFAULT_CAPACITY, TWO_X_STRESS_TEST_CAPACITY

MiB = 1024 * 1024
GiB = 1024 * MiB
CHUNK = MiB


def available_memory():
    if os.name == 'nt':
        class MemoryStatus(ctypes.Structure):
            _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong),
                ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                ('ullAvailExtendedVirtual', ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        function = ctypes.windll.kernel32.GlobalMemoryStatusEx
        function.argtypes = [ctypes.POINTER(MemoryStatus)]
        function.restype = ctypes.c_int
        if not function(ctypes.byref(status)):
            raise OSError('GlobalMemoryStatusEx failed')
        return status.ullAvailPhys
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise OSError('Available physical memory is not exposed on this platform')


def peak_rss_bytes():
    if os.name == 'nt':
        class Counters(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong),
                ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        process = kernel.GetCurrentProcess()
        function = ctypes.windll.psapi.GetProcessMemoryInfo
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        function.restype = ctypes.c_int
        if not function(process, ctypes.byref(counters), counters.cb):
            raise OSError('GetProcessMemoryInfo failed')
        return counters.PeakWorkingSetSize
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == 'darwin' else value * 1024


def digest_file(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as source:
        while chunk := source.read(CHUNK):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def source_artifacts(directory, manifest):
    version = next(name.split('-')[1][1:] for name in manifest['files']
                   if name.endswith('-setup-x64.exe'))
    archive_names = {item['name'] for item in manifest['archives']}
    by_group = []
    for artifact_id, artifact_name, expected_archive in (
        (30, 'release-files-attempt-1', 'release-files-attempt-1.zip'),
        (31, 'release-linux-files-attempt-1', 'release-linux-files-attempt-1.zip')):
        path = Path(directory) / expected_archive
        size, sha = digest_file(path)
        if expected_archive not in archive_names:
            raise ValueError('Generated archive inventory differs from the fixture manifest')
        by_group.append(dict(id=artifact_id, name=artifact_name, path=str(path), size_in_bytes=size,
            digest='sha256:' + sha, expired=False,
            workflow_run=dict(id=12, head_sha=manifest['source'])))
    return version, by_group


def streaming_parse(directory, manifest, profile):
    version, artifacts = source_artifacts(directory, manifest)
    index = {item['id']: item for item in artifacts}
    max_read = [0]

    class LocalTransport:
        def __call__(self, route, **kwargs):
            if route == '/actions/runs/12/artifacts?per_page=100':
                return {'total_count': len(artifacts), 'artifacts': artifacts}
            artifact_id = int(route.split('/')[3])
            item = index[artifact_id]
            sink = kwargs['sink']
            with Path(item['path']).open('rb') as source:
                while True:
                    chunk = source.read(sink.workspace.policy.max_buffer_bytes)
                    max_read[0] = max(max_read[0], len(chunk))
                    if not chunk:
                        return None
                    sink.write(chunk)

    policy = DEFAULT_CAPACITY if profile == 'operational' else TWO_X_STRESS_TEST_CAPACITY
    workspace_parent = Path(directory) / 'benchmark-workspace'
    workspace_parent.mkdir()
    workspace = ArtifactWorkspace(policy, parent=workspace_parent)
    try:
        started = time.perf_counter()
        cpu_started = time.process_time()
        files, provenance = promotion.staged_artifact_files(LocalTransport(),
            dict(id=12, run_attempt=1, head_sha=manifest['source']), version, False, workspace)
        identities = {name: promotion.file_identity(value) for name, value in sorted(files.items())}
        elapsed = time.perf_counter() - started
        cpu = time.process_time() - cpu_started
        return dict(mode='streaming parser', profile=profile, wall_seconds=elapsed, cpu_seconds=cpu,
            peak_rss_bytes=peak_rss_bytes(), archive_bytes=sum(a['size_in_bytes'] for a in artifacts),
            expanded_bytes=workspace.expanded_bytes, peak_temp_disk_bytes=workspace.disk_bytes,
            largest_read_chunk_bytes=max_read[0], provenance=provenance,
            files={name: dict(size=size, sha256=sha) for name, (size, sha) in identities.items()},
            input_mib_per_second=round(sum(a['size_in_bytes'] for a in artifacts) / MiB / elapsed, 2))
    finally:
        workspace.close()


def legacy_memory_parse(directory, manifest):
    """Reproduce the previous bytes-in-memory parser for the default-size comparison."""
    version, artifacts = source_artifacts(directory, manifest)
    expected_prefix = 'rolauncher-v' + version
    retained = {}
    started = time.perf_counter()
    cpu_started = time.process_time()
    max_read = 0
    for item in artifacts:
        raw = Path(item['path']).read_bytes()
        max_read = max(max_read, len(raw))
        if len(raw) != item['size_in_bytes'] or hashlib.sha256(raw).hexdigest() != item['digest'].removeprefix('sha256:'):
            raise ValueError('Legacy parser archive digest mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            if not all(name.startswith(expected_prefix) for name in names):
                raise ValueError('Legacy parser found an unexpected archive entry')
            for name in names:
                retained[name] = archive.read(name)
    elapsed = time.perf_counter() - started
    cpu = time.process_time() - cpu_started
    return dict(mode='legacy in-memory parser simulation', profile='operational', wall_seconds=elapsed,
        cpu_seconds=cpu, peak_rss_bytes=peak_rss_bytes(), archive_bytes=sum(a['size_in_bytes'] for a in artifacts),
        expanded_bytes=sum(map(len, retained.values())), peak_temp_disk_bytes=0,
        largest_read_chunk_bytes=max_read, files={name: dict(size=len(value), sha256=hashlib.sha256(value).hexdigest())
            for name, value in sorted(retained.items())},
        input_mib_per_second=round(sum(a['size_in_bytes'] for a in artifacts) / MiB / elapsed, 2))


def run_worker(mode, directory, manifest_path, profile='operational'):
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    if mode == 'legacy':
        result = legacy_memory_parse(directory, manifest)
    else:
        result = streaming_parse(directory, manifest, profile)
    print(json.dumps(result, sort_keys=True))


def worker_result(mode, directory, manifest_path, profile='operational'):
    command = [sys.executable, str(Path(__file__).resolve()), '--worker', mode,
               '--profile', '2x-test', '--output', str(Path(directory) / 'worker-placeholder'),
               '--directory', str(directory), '--manifest', str(manifest_path), '--worker-profile', profile]
    result = subprocess.run(command, capture_output=True, text=True, timeout=3600, check=False)
    if result.returncode:
        raise RuntimeError(f'{mode} benchmark worker failed: {result.stderr[-4000:]}')
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError(f'{mode} benchmark worker returned invalid evidence: {result.stderr[-4000:]}') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('2x-test',), required=True)
    parser.add_argument('--confirm-heavy-local-only', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reserve-disk-mib', type=int, default=2048)
    parser.add_argument('--reserve-memory-mib', type=int, default=2048)
    parser.add_argument('--worker', choices=('legacy', 'streaming'))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--worker-profile', choices=('operational', '2x-test'), default='operational')
    args = parser.parse_args(argv)
    if args.worker:
        if args.directory is None or args.manifest is None:
            parser.error('benchmark worker requires --directory and --manifest')
        run_worker(args.worker, args.directory, args.manifest, args.worker_profile)
        return 0
    if args.output is None:
        parser.error('--output is required')
    if not args.confirm_heavy_local_only:
        parser.error('--confirm-heavy-local-only is required; this benchmark never publishes')
    output = args.output.resolve()
    if output.exists():
        parser.error('Output must be a new directory; no existing files will be overwritten')
    if type(args.reserve_disk_mib) is not int or args.reserve_disk_mib < 1024:
        parser.error('--reserve-disk-mib must preserve at least 1024 MiB')
    if type(args.reserve_memory_mib) is not int or args.reserve_memory_mib < 1024:
        parser.error('--reserve-memory-mib must preserve at least 1024 MiB')
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    free_disk = shutil.disk_usage(parent).free
    free_memory = available_memory()
    required_disk = 5 * GiB + args.reserve_disk_mib * MiB
    required_memory = 256 * MiB + args.reserve_memory_mib * MiB
    legacy_memory_required = 2 * GiB + args.reserve_memory_mib * MiB
    preflight = dict(free_disk_bytes=free_disk, required_disk_bytes=required_disk,
        available_memory_bytes=free_memory, required_memory_bytes=required_memory,
        legacy_simulation_memory_required_bytes=legacy_memory_required,
        legacy_simulation_available=free_memory >= legacy_memory_required,
        output=str(output), profile=args.profile, github_requests=0, publisher_calls=0)
    if free_disk < required_disk or free_memory < required_memory:
        parser.error('Resource preflight failed: ' + json.dumps(preflight, sort_keys=True))

    output.mkdir(parents=True)
    working = output / 'work'
    working.mkdir()
    try:
        benchmark_started = time.perf_counter()
        baseline_dir = working / 'operational-fixture'
        baseline_manifest = fixtures.package(baseline_dir, 192 * MiB, 96 * MiB,
            entropy=True, profile='operational')
        baseline_file = baseline_dir / 'manifest.json'
        if preflight['legacy_simulation_available']:
            baseline_legacy = worker_result('legacy', baseline_dir, baseline_file)
        else:
            baseline_legacy = dict(status='NOT RUN', reason='legacy memory preflight would violate the configured reserve')
        baseline_stream = worker_result('streaming', baseline_dir, baseline_file, 'operational')

        stress_dir = working / '2x-fixture'
        stress_manifest = fixtures.package(stress_dir, 512 * MiB, 256 * MiB,
            entropy=True, profile='2x-test')
        stress_file = stress_dir / 'manifest.json'
        stress_stream = worker_result('streaming', stress_dir, stress_file, '2x-test')
        report = dict(status='PASS', profile='local 2x streaming stress; no live API or Publisher',
            source=stress_manifest['source'], preflight=preflight, elapsed_seconds=round(time.perf_counter()-benchmark_started, 2),
            comparisons=dict(operational_legacy=baseline_legacy, operational_streaming=baseline_stream,
                two_x_streaming=stress_stream),
            fixture_manifests=dict(operational=baseline_manifest, two_x=stress_manifest),
            live_github_transfer='NOT RUN', live_publisher='NOT RUN', hosted_ci='NOT RUN')
        report_path = output / 'benchmark.json'
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        if working.resolve().parent == output.resolve():
            shutil.rmtree(working, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
