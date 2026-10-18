"""Stream inert size fixtures; no application build, network or publication."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import random
import tarfile
import zipfile

import release_promotion as promotion
import sandbox_fixtures as fixtures

MiB=1024*1024
CHUNK=MiB


def capacity(windows_bytes, linux_bytes):
    promotion.require(all(type(n) is int and n>0 for n in (windows_bytes,linux_bytes)), 'Positive fixture sizes required')
    promotion.require(windows_bytes<=promotion.MAX_ENTRY_BYTES
        and linux_bytes+65536<=promotion.MAX_ENTRY_BYTES, 'Fixture exceeds unchanged 256 MiB entry limit')
    promotion.require(windows_bytes+linux_bytes+2*MiB<=promotion.MAX_EXPANDED_BYTES,
                      'Fixture exceeds unchanged aggregate budget')
    return dict(windows_bytes=windows_bytes,linux_payload_bytes=linux_bytes,
                archive_limit=promotion.MAX_ARCHIVE_BYTES,entry_limit=promotion.MAX_ENTRY_BYTES,
                aggregate_limit=promotion.MAX_EXPANDED_BYTES,
                two_x='BLOCKED: 512 MiB Windows exceeds entry bound; combined 768 MiB exceeds aggregate bound')


class Padding(io.RawIOBase):
    def __init__(self,size,entropy=False):
        self.remaining=size
        self.random=random.Random(71574088) if entropy else None
    def read(self,size=-1):
        size=min(CHUNK,self.remaining,size if size>=0 else CHUNK)
        self.remaining-=size
        return self.random.randbytes(size) if self.random else bytes(size)


def write_inert(path,size,entropy=False):
    notice=fixtures.NOTICE+b'NOT-A-PE-EXECUTABLE\n'
    promotion.require(len(notice)<=size<=promotion.MAX_ENTRY_BYTES,'Inert file size')
    padding=Padding(size-len(notice),entropy)
    with Path(path).open('xb') as output:
        output.write(notice)
        while chunk:=padding.read(CHUNK):output.write(chunk)


def sha256(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk:=source.read(CHUNK):digest.update(chunk)
    return digest.hexdigest()


def package(output,windows_bytes=256*MiB,linux_bytes=128*MiB,entropy=False,root=fixtures.ROOT,sha=None):
    report=capacity(windows_bytes,linux_bytes)
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
    write_inert(payload/setup,windows_bytes,entropy)
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
    promotion.require(expanded<=promotion.MAX_EXPANDED_BYTES,'Expanded fixture budget exceeded')
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
        promotion.require(target.stat().st_size<=promotion.MAX_ARCHIVE_BYTES,'Outer artifact exceeds unchanged archive limit')
        with zipfile.ZipFile(target) as archive:
            promotion.require(archive.testzip() is None,'Large fixture archive CRC failure')
        archives.append(dict(name=target.name,size=target.stat().st_size,sha256=sha256(target)))
    report.update(source=sha,entropy='deterministic pseudorandom' if entropy else 'compressible zero padding',
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
    args=parser.parse_args()
    print(json.dumps(package(args.output,args.windows_mib*MiB,args.linux_mib*MiB,args.entropy),indent=2))
