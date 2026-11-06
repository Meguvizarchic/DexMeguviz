"""Build an isolated v12 string-use fixture from a pinned project-original DEX."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path

SOURCE_SHA='65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04'
FIXTURE_SHA='67e58385794f6bc1f8fe56a30bbcb4a4eb973e26b4e6449a52ed0c671668292a'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    source=args.source.read_bytes();assert hashlib.sha256(source).hexdigest()==SOURCE_SHA
    old=b'\x0bused-string\x00';new=b'\x07used\xed\xa0\xbd\xed\xb8\x80x\x00'
    assert len(old)==len(new) and source.count(old)==1
    out=bytearray(source.replace(old,new));out[12:32]=hashlib.sha1(out[32:]).digest();struct.pack_into('<I',out,8,zlib.adler32(out[12:])&0xffffffff)
    assert hashlib.sha256(out).hexdigest()==FIXTURE_SHA
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'string-utf16-v12.dex').write_bytes(out)
    manifest={'schema_version':1,'source':'generated/use_relations/string-normal-jumbo.dex','source_sha256':SOURCE_SHA,'fixture':'string-utf16-v12.dex','fixture_sha256':FIXTURE_SHA,'bytes':len(out),'target_index':10,'utf16_units':[117,115,101,100,55357,56832,120],'instruction_pcs':[0,2],'scope':'Project-original static DEX; no ART or runtime claim'}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
