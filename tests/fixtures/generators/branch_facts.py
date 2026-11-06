"""Generate a DEX with forward, backward and self-loop branch encodings."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
import switch_facts

WORDS = (0x0228, 0x000e, 0x0029, 3, 0x000e, 0x002a, 4, 0, 0x000e,
         0x0032, 3, 0x000e, 0x0038, 0xfffd, 0x002a, 0, 0,
         0x003b, 0xfffd, 0x000e, 0x000e, 0x000e, 0x000e, 0x000e, 0x000e, 0x000e)
CASES = [[0, 2, 0x28, 'unconditional'], [2, 5, 0x29, 'unconditional'],
         [5, 9, 0x2a, 'unconditional'], [9, 12, 0x32, 'conditional'],
         [12, 9, 0x38, 'conditional'], [14, 14, 0x2a, 'unconditional'],
         [17, 14, 0x3b, 'conditional']]

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    original,code_at=switch_facts.build(); image=bytearray(original)
    assert len(WORDS)==26 and struct.unpack_from('<I',image,code_at+12)[0]==len(WORDS)
    struct.pack_into('<26H',image,code_at+16,*WORDS)
    image[12:32]=hashlib.sha1(image[32:]).digest()
    struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'branch-facts.dex').write_bytes(image)
    (args.output/'expected.json').write_text(json.dumps({'sha256':hashlib.sha256(image).hexdigest(),
        'code_offset':code_at,'cases':CASES,'scope':'encoded branch destinations; not reachability or runtime control flow'},indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
