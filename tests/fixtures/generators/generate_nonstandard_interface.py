"""Generate the synthetic nonstandard-interface caller relation DEX."""
from pathlib import Path
import argparse,hashlib,json,runpy
p=argparse.ArgumentParser();p.add_argument('--generator',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);g=runpy.run_path(str(a.generator));data=g['build']('Lq08/IA;','Lq08/Parent;',(),('Lq08/ICommon;',),False,0x601);file=a.out/'interface-a-bad-super.dex';file.write_bytes(data);(a.out/'manifest.json').write_text(json.dumps({'file':file.name,'sha256':hashlib.sha256(data).hexdigest(),'scope':'static metadata fixture, no ART validity claim'},indent=2)+'\n',encoding='utf-8');print('PASS generated nonstandard interface byte fixture')
