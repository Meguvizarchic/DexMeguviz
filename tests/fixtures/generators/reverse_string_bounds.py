"""Original structural DEX for direct string join 4096/4097 boundaries."""
from pathlib import Path
import argparse,hashlib,struct,zlib
from reverse_fixture_base import build
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
owner='Lbounds/StringOwner;';name='use';target='body-marker';initial=build(owner,name,'V',[],used=[target]);base=struct.unpack_from('<I',initial,56)[0];assert base<100
files={}
for n in (4096,4097):
 data=build(owner,name,'V',[],used=[target],pool=['extra-%05d'%i for i in range(n-base)]);assert struct.unpack_from('<I',data,56)[0]==n;files['right-%d.dex'%n]=data
for n in (4096,4097):
 data=build(owner,name,'V',[],used=[target]*n);files['left-%d.dex'%n]=data
# Corrupt the first opcode without damaging metadata or header checksums.
data=bytearray(files['right-4097.dex']);map_at=struct.unpack_from('<I',data,52)[0];count=struct.unpack_from('<I',data,map_at)[0];code=[struct.unpack_from('<HHII',data,map_at+4+12*i)[3] for i in range(count) if struct.unpack_from('<H',data,map_at+4+12*i)[0]==0x2001];assert len(code)==1;code=code[0];assert struct.unpack_from('<H',data,code+16)[0]&255==0x1a;data[code+16]=0x73;data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff);files['corrupt-right-4097.dex']=bytes(data)
for name,data in files.items():
 with (a.output/name).open('xb') as f:f.write(data)
print('PASS generated', {name:hashlib.sha256(data).hexdigest() for name,data in files.items()})
