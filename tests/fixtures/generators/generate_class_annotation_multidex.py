"""Generate a deterministic test-only APK with two identical annotation DEX occurrences."""
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_STORED
import argparse
p=argparse.ArgumentParser();p.add_argument('--dex',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
data=a.dex.read_bytes()
with ZipFile(a.out,'x') as archive:
    for name in ('classes.dex','classes2.dex'):
        item=ZipInfo(name,(2020,1,1,0,0,0));item.compress_type=ZIP_STORED;archive.writestr(item,data)
print('PASS generated two-DEX fixture')
