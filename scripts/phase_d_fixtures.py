"""Stream inert size fixtures; no application build, network or publication."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import release_promotion as promotion
import sandbox_fixtures as fixtures

MiB=1024*1024
CHUNK=MiB
SEED=71574088


def capacity(windows_bytes, linux_bytes, profile='operational'):
    policy=promotion.capacity_policy() if profile=='operational' else promotion_capacity_test()
    promotion.require(all(type(n) is int and n>0 for n in (windows_bytes,linux_bytes)), 'Positive fixture sizes required')
    promotion.require(profile in ('operational','2x-test'),'Unknown fixture profile')
    if profile=='2x-test':
        promotion.require(windows_bytes>=512*MiB and linux_bytes>=256*MiB,
                          '2x test profile requires 512 MiB Windows and 256 MiB Linux payloads')
    promotion.require(windows_bytes<=policy.max_entry_bytes
        and linux_bytes+65536<=policy.max_entry_bytes, 'Fixture exceeds selected entry limit')
    promotion.require(windows_bytes+linux_bytes+2*MiB<=policy.max_expanded_bytes,
                      'Fixture exceeds selected aggregate budget')
    return dict(windows_bytes=windows_bytes,linux_payload_bytes=linux_bytes,
                profile='operational defaults' if profile=='operational' else 'local 2x stress test only',
                archive_limit=policy.max_archive_bytes,entry_limit=policy.max_entry_bytes,
                aggregate_limit=policy.max_expanded_bytes,
                two_x='BLOCKED under operational defaults' if profile=='operational'
                    else 'isolated test capacity; never used by Publisher')


def promotion_capacity_test():
    from phase_d_capacity import TWO_X_STRESS_TEST_CAPACITY
    return TWO_X_STRESS_TEST_CAPACITY


class Padding(io.RawIOBase):
    def __init__(self,size,entropy=False):
        self.remaining=size
        self.entropy=entropy
        self.counter=0
    def read(self,size=-1):
        size=min(CHUNK,self.remaining,size if size>=0 else CHUNK)
        self.remaining-=size
        if not size:return b''
        if not self.entropy:return bytes(size)
        seed=b'phase-d-fixture-v1:'+str(SEED).encode()+b':'+str(self.counter).encode()
        self.counter+=1
        return hashlib.shake_256(seed).digest(size)


def write_inert(path,size,entropy=False,max_file_bytes=None):
    notice=fixtures.NOTICE+b'NOT-A-PE-EXECUTABLE\n'
    if max_file_bytes is None:max_file_bytes=promotion.capacity_policy().max_entry_bytes
    promotion.require(len(notice)<=size<=max_file_bytes,'Inert file size')
    padding=Padding(size-len(notice),entropy)
    with Path(path).open('xb') as output:
        output.write(notice)
        while chunk:=padding.read(CHUNK):output.write(chunk)


def sha256(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk:=source.read(CHUNK):digest.update(chunk)
    return digest.hexdigest()


def package(output,windows_bytes=256*MiB,linux_bytes=128*MiB,entropy=False,root=fixtures.ROOT,sha=None,profile='operational'):
    report=capacity(windows_bytes,linux_bytes,profile)
    policy=promotion.capacity_policy() if profile=='operational' else promotion_capacity_test()
    output=Path(output)
    output.mkdir(parents=True,exist_ok=False)
    sha=sha or fixtures.git(root,'rev-parse','HEAD').decode().strip()
    payload=output/'payload'
    files=fixtures.package('windows',payload,root,sha)
    files.update(fixtures.package('linux',payload,root,sha))
    setup=next(n for n in files if n.endswith('-setup-x64.exe'))
    prefix=setup.removesuffix('-setup-x64.exe')
    # Only replace our newly generated local placeholders, never an existing output directory.
    (payload/setup).unlink()
    write_inert(payload/setup,windows_bytes,entropy,policy.max_entry_bytes)
    linux=prefix+'-linux-x64.tar.gz'
    with (payload/linux).open('wb') as output_file:
        with gzip.GzipFile(fileobj=output_file,filename='',mode='wb',mtime=0,compresslevel=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
                notice=fixtures.NOTICE+('Synthetic source: '+sha+'\n').encode()
                info=tarfile.TarInfo('SANDBOX-ONLY.txt');info.size=len(notice);info.mode=0o644
                archive.addfile(info,io.BytesIO(notice))
                info=tarfile.TarInfo('INERT-PADDING.bin');info.size=linux_bytes;info.mode=0o644
                archive.addfile(info,Padding(linux_bytes,entropy))
    for suffix,names in (('-SHA256SUMS.txt',[prefix+s for s in ('-setup-x64.exe','-windows-x64.zip','-source.zip')]),
                         ('-linux-SHA256SUMS.txt',[linux])):
        (payload/(prefix+suffix)).write_text(''.join(sha256(payload/n)+'  '+n+'\n' for n in sorted(names)),encoding='ascii')
    groups={'release-files-attempt-1':[prefix+s for s in ('-setup-x64.exe','-windows-x64.zip','-source.zip','-SHA256SUMS.txt')],
            'release-linux-files-attempt-1':[linux,prefix+'-linux-SHA256SUMS.txt']}
    expanded=sum(p.stat().st_size for p in payload.iterdir())
    promotion.require(expanded<=policy.max_expanded_bytes,'Expanded fixture budget exceeded')
    archives=[]
    for name,names in groups.items():
        target=output/(name+'.zip')
        with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as archive:
            for name in sorted(names):
                # Explicit fixed ZIP metadata; streaming write keeps memory bounded.
                info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                info.create_system=3;info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED
                with (payload/name).open('rb') as source,archive.open(info,'w') as dest:
                    while chunk:=source.read(CHUNK):dest.write(chunk)
        promotion.require(target.stat().st_size<=policy.max_archive_bytes,'Outer artifact exceeds selected archive limit')
        with zipfile.ZipFile(target) as archive:
            promotion.require(archive.testzip() is None,'Large fixture archive CRC failure')
        archives.append(dict(name=target.name,size=target.stat().st_size,sha256=sha256(target)))
    report.update(source=sha,entropy='deterministic SHAKE-256 pseudorandom' if entropy else 'compressible zero padding',
        fixture_seed=SEED if entropy else None,
        fixture_algorithm='SHAKE-256(seed, counter), generated in <=1 MiB chunks' if entropy else 'zero-fill, generated in <=1 MiB chunks',
        expanded_bytes=expanded,archives=archives,
        files={p.name:dict(size=p.stat().st_size,sha256=sha256(p)) for p in sorted(payload.iterdir())},
        evidence='LOCAL GENERATED ONLY; no Actions upload or release mutation')
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--windows-mib',type=int,default=256)
    parser.add_argument('--linux-mib',type=int,default=128)
    parser.add_argument('--entropy',action='store_true')
    parser.add_argument('--profile',choices=('operational','2x-test'),default='operational')
    parser.add_argument('--confirm-local-only',action='store_true')
    args=parser.parse_args()
    if args.profile=='2x-test':promotion.require(args.confirm_local_only,
        '2x fixture generation requires --confirm-local-only and never publishes artifacts')
    print(json.dumps(package(args.output,args.windows_mib*MiB,args.linux_mib*MiB,
        args.entropy,profile=args.profile),indent=2))
