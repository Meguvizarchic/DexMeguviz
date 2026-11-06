"""Original static DEX fixture: one callsite in a class implementing Lifx/Left."""
import argparse,hashlib,struct,zlib
from pathlib import Path
import reverse_fixture_base as base

def build():
    owner='Lifx/Child;';interface='Lifx/Left;'
    data=bytearray(base.build(owner,'uses','V',(interface,),target=(owner,'sink','V',())))
    count,protos=struct.unpack_from('<II',data,72);class_count,classes=struct.unpack_from('<II',data,96)
    assert class_count==1 and count==2
    lists=[struct.unpack_from('<I',data,protos+12*i+8)[0] for i in range(count)]
    nonempty=[x for x in lists if x];assert len(nonempty)==1
    at=nonempty[0];assert struct.unpack_from('<I',data,at)[0]==1
    types=struct.unpack_from('<I',data,68)[0];strings=struct.unpack_from('<I',data,60)[0];interface_id=struct.unpack_from('<H',data,at+4)[0]
    string_id=struct.unpack_from('<I',data,types+4*interface_id)[0];string_at=struct.unpack_from('<I',data,strings+4*string_id)[0]
    assert data[string_at+1:string_at+1+len(interface)]==interface.encode('ascii')
    assert struct.unpack_from('<I',data,classes+12)[0]==0
    struct.pack_into('<I',data,classes+12,at)
    data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    return bytes(data)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    data=build();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('xb') as f:f.write(data)
    print(hashlib.sha256(data).hexdigest())
