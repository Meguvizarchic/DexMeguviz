"""Independent byte checks for the fixed class/type SQL oracle input."""
import argparse
import hashlib
import struct
import zlib
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
data=a.fixture.read_bytes()
assert hashlib.sha256(data).hexdigest()=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
assert data[:8]==b'dex\n035\0' and data[12:32]==hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
u32=lambda at:struct.unpack_from('<I',data,at)[0]
assert u32(32)==len(data) and u32(36)==112
strings=[]
for index in range(u32(56)):
    at=u32(u32(60)+4*index);length=0
    for shift in range(0,35,7):
        b=data[at];at+=1;length|=(b&127)<<shift
        if not b&128:break
    else:raise AssertionError('invalid uleb')
    end=data.index(0,at);raw=data[at:end];assert len(raw)==length
    strings.append(raw.decode('ascii'))
types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))]
assert types==['I','J','Lcatalog/Base;','Lcatalog/Child;','Lcatalog/InterfaceA;',
               'Lcatalog/InterfaceB;','Lexternal/External;','Ljava/lang/Object;','V']
expected=[(7,1,None,252),(4,1537,7,284),(5,1537,7,316),(2,1,7,348),(3,1025,2,380)]
assert u32(96)==len(expected)
for ordinal,(type_id,flags,parent,offset) in enumerate(expected):
    at=u32(100)+ordinal*32
    actual_id,actual_flags,actual_parent=struct.unpack_from('<III',data,at)
    assert (actual_id,actual_flags,None if actual_parent==0xffffffff else actual_parent,at)==(type_id,flags,parent,offset)
assert len({row[0] for row in expected})==len(expected) and 6 not in {row[0] for row in expected}
print('PASS fixed DEX SHA/checksums, nine type descriptors and five class definitions')
