"""Deterministic inert packages from exact Git objects; never builds an application."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
NOTICE = b'SANDBOX ONLY: inert fixture, not executable application software.\n'
MAX_SOURCE_BYTES = 256 * 1024 * 1024


def git(root, *args):
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(root), *args],
                            check=True, capture_output=True, timeout=60)
    return result.stdout


def source_files(root, sha):
    if not re.fullmatch('[a-f0-9]{40}', sha):
        raise ValueError('Exact synthetic source commit required')
    records = git(root, 'ls-tree', '-rz', '--full-tree', sha).split(b'\0')
    if not 0 < len(records) - 1 < 5000:
        raise ValueError('Source tree count exceeds publisher contract')
    files, size = {}, 0
    for record in records:
        if not record:
            continue
        header, raw_name = record.split(b'\t', 1)
        mode, kind, blob = header.decode('ascii').split()
        name = raw_name.decode('utf-8')
        if mode not in ('100644', '100755') or kind != 'blob':
            raise ValueError('Source symlinks/submodules are unsupported')
        if name.startswith('/') or '\\' in name or {'.', '..'} & set(name.split('/')):
            raise ValueError('Ambiguous source path')
        data = git(root, 'cat-file', 'blob', blob)
        size += len(data)
        if size > MAX_SOURCE_BYTES:
            raise ValueError('Source expansion exceeds publisher contract')
        files[name] = data
    return files


def zip_bytes(files):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return result.getvalue()


def tar_bytes(files):
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, filename='', mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                archive.addfile(info, io.BytesIO(data))
    return result.getvalue()


def package(platform, output, root=ROOT, sha=None):
    if platform not in ('windows', 'linux'):
        raise ValueError('Unknown fixture platform')
    root, output = Path(root), Path(output)
    sha = sha or git(root, 'rev-parse', 'HEAD').decode().strip()
    files = source_files(root, sha)
    manifest = tomllib.loads(files['Cargo.toml'].decode())
    version = manifest['package']['version']
    if not re.fullmatch(r'0\.(0\.900|0\.901|([1-9]|1[0-9]|20)\.0)', version):
        raise ValueError('Version is outside the reviewed synthetic fixture registry')
    if not files['README.md'].startswith(('# RoLauncher ' + version + '\n').encode()):
        raise ValueError('Synthetic metadata must match the exact source commit')
    lock = tomllib.loads(files['Cargo.lock'].decode())
    if next(p for p in lock['package'] if p['name'] == 'rolauncher')['version'] != version:
        raise ValueError('Synthetic lock version mismatch')
    required = ('AGENTS.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md')
    payload = {name: files[name] for name in required}
    payload['SANDBOX-ONLY.txt'] = NOTICE + ('Synthetic source: ' + sha + '\n').encode()
    prefix = 'rolauncher-v' + version
    if platform == 'windows':
        # Deliberately invalid executable: no PE header, launcher, interpreter or entrypoint.
        packages = {prefix + '-setup-x64.exe': NOTICE + b'NOT-A-PE-EXECUTABLE\n',
                    prefix + '-windows-x64.zip': zip_bytes(payload),
                    prefix + '-source.zip': zip_bytes(files)}
        checksum_name = prefix + '-SHA256SUMS.txt'
    else:
        packages = {prefix + '-linux-x64.tar.gz': tar_bytes(payload)}
        checksum_name = prefix + '-linux-SHA256SUMS.txt'
    packages[checksum_name] = ''.join(
        hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
        for name, data in sorted(packages.items())).encode('ascii')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in packages.items():
        target = output / name
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Refuse to replace different fixture bytes: ' + name)
        target.write_bytes(data)
    return packages


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=('windows', 'linux'))
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    for name, data in package(args.platform, args.output).items():
        print(hashlib.sha256(data).hexdigest(), len(data), name)
