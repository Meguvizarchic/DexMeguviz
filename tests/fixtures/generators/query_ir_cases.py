from pathlib import Path
import argparse,hashlib,json,struct,zlib
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
data=bytearray(args.source.read_bytes());pattern=b'\x06second\0';assert data.count(pattern)==1
at=data.index(pattern);data[at:at+len(pattern)]=b'\x06zzzzzz\0'
data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:]))
args.out.mkdir(parents=True,exist_ok=True);(args.out/'late-better.dex').write_bytes(data)
(args.out/'expected.json').write_text(json.dumps({'schema_version':1,'source':'authored exact-length symbol variant, never engine output','expected_late_sort_winner':'zzzzzz','sha256':hashlib.sha256(data).hexdigest()},indent=2)+'\n',encoding='utf-8')
