#!/usr/bin/env python3
"""Write a manifest for a published VPK; compatible with VitaTunnel's strict parser."""
import argparse, hashlib, pathlib, re
p=argparse.ArgumentParser()
p.add_argument('vpk',type=pathlib.Path)
p.add_argument('--title-id',required=True)
p.add_argument('--version',required=True)
p.add_argument('--url',required=True)
p.add_argument('--out',default='tunnel/manifest.txt',type=pathlib.Path)
a=p.parse_args()
if not re.fullmatch(r'[A-Z0-9]{9}',a.title_id) or a.title_id=='VITATUNN1':p.error('invalid title ID')
if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,48}',a.version):p.error('invalid version')
if not a.url.startswith('https://github.com/') or '/releases/download/' not in a.url or not a.url.endswith('.vpk'):p.error('url must be a GitHub Release VPK')
h=hashlib.sha256()
with a.vpk.open('rb') as f:
    for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
a.out.parent.mkdir(parents=True,exist_ok=True)
a.out.write_text(f'version={a.version}\ntitle_id={a.title_id}\nvpk_url={a.url}\nsha256={h.hexdigest()}\n')
print(f'{a.out}  SHA256={h.hexdigest()}')
