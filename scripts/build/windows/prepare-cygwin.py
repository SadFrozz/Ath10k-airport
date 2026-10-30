from pathlib import Path
import lzma,re,json,urllib.request,tarfile,hashlib,concurrent.futures,shutil,sys
import argparse
repo=Path(__file__).resolve().parents[3]
tool=repo/'.cache/windows-kext';root=tool/'cygwin';cache=tool/'packages'
cache.mkdir(parents=True,exist_ok=True);root.mkdir(exist_ok=True)
parser=argparse.ArgumentParser(description="Extract pinned Cygwin build packages locally, without running an installer.")
parser.add_argument('--mirror',default='https://mirrors.dotsrc.org/cygwin/')
args=parser.parse_args();url=args.mirror.rstrip('/')+'/'
sys.path.insert(0,str(tool/'python'))
try:import zstandard
except ImportError:raise SystemExit('Install zstandard==0.25.0 into .cache/windows-kext/python with pip --target first')
packages=json.loads((repo/'scripts/build/windows/cygwin-packages.json').read_text());selected=set(packages)
print(f'{len(selected)} packages, {sum(packages[n]["size"] for n in selected)//1048576} MiB download',flush=True)
def fetch(name):
    p=packages[name];dest=cache/Path(p['path']).name
    if not dest.exists():
        with urllib.request.urlopen(url+p['path'],timeout=120) as r,dest.open('wb') as f:shutil.copyfileobj(r,f)
    digest=hashlib.sha512(dest.read_bytes()).hexdigest()
    if digest!=p['sha512']:raise ValueError('SHA512 mismatch: '+name)
    return name,dest
links=[]
def normalize(name):
    name=name.lstrip('./')
    if name.startswith('usr/bin/'):name='bin/'+name[8:]
    if name.startswith('usr/lib/'):name='lib/'+name[8:]
    return name
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    for name,path in pool.map(fetch,sorted(selected)):
        file=path.open('rb');reader=zstandard.ZstdDecompressor().stream_reader(file) if path.suffix=='.zst' else file
        with tarfile.open(fileobj=reader,mode='r|*') as archive:
            for m in archive:
                if '/man/' in m.name or any(c in m.name for c in '<>:"|?*'):continue
                target=root/normalize(m.name)
                if not target.resolve().is_relative_to(root.resolve()):raise ValueError('Unsafe archive path')
                if m.isdir():target.mkdir(parents=True,exist_ok=True)
                elif m.isfile():
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with archive.extractfile(m) as r,target.open('wb') as f:shutil.copyfileobj(r,f)
                elif m.issym() or m.islnk():links.append((target,m.linkname,m.islnk()))
        print('Extracted '+name,flush=True)
        reader.close();file.close()
for _ in range(4):
    pending=[]
    for target,link,hard in links:
        source=root/normalize(link) if hard or link.startswith('/') else target.parent/link
        if source.resolve().is_relative_to(root.resolve()) and source.is_file():
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        else:pending.append((target,link,hard))
    links=pending
(tool/'cygwin-unresolved-links.json').write_text(json.dumps([[str(p.relative_to(root)),s,h] for p,s,h in links],indent=2))
print('Portable extraction complete; unresolved links: '+str(len(links)),flush=True)

(root/'tmp').mkdir(exist_ok=True)
if not (root/'bin/sh.exe').exists():shutil.copyfile(root/'bin/bash.exe',root/'bin/sh.exe')
