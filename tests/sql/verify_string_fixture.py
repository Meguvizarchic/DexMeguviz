"""Independently check the raw string IDs used by the SQL ordinary-table oracle."""
import hashlib, struct, sys, zlib
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(data).hexdigest() == '2b2736d4e9feb01f7c7a8d5e70633fe8f72cdf92b18d294367f6f6068d059016'
assert data[:8] == b'dex\n035\0' and data[12:32] == hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff
count, offset = struct.unpack_from('<II', data, 56)
assert count == 8
expected = [(0,b''), (18,b'Ljava/lang/Object;'), (16,b'Lsample/Example;'), (1,b'V'),
            (8,b'external'), (6,b'locate'), (6,b'second'),
            (8,bytes.fromhex('e99baaeda0bdedb880c0807461696c'))]
observed = []
for index in range(count):
    at = struct.unpack_from('<I', data, offset + index * 4)[0]
    length = 0
    for shift in range(0,35,7):
        byte = data[at]; at += 1; length |= (byte & 127) << shift
        if not byte & 128: break
    else: raise AssertionError('invalid ULEB')
    end = data.index(0, at)
    observed.append((length, data[at:end]))
assert observed == expected
root=Path(__file__).resolve().parents[2]/'tests/fixtures/generated/sql-unicode33-bound'
cases={
    'feff':('9d453f1aa48768f46fa0f21eaee5444da3d8b2e870ebd53c43766506ffdd1f85','efbbbf'),
    'fffe':('bbd954db3ac77b7c5782834dcc1fbd033d4ccc377291f5cb9599098f6b1b51fa','efbfbe'),
    'high':('de6d68547560eb64aef7c4c42b203c5f1eb3882dc3704b8716e6601981ab2212','eda080'),
    'low':('1b59c075d9b1a2a173a4e0dd2407c018e2d62efdfa953dcceab7ccecf9b66ed2','edbfbf'),
    'endnul':('b5e684d9617d4a9f517323d45afe765e530badfff559accc06e2f7ce0673e562','7461696cc080'),
    'long':('a5b2529dc71d714efe181a811388b8393b6f62a52a526757a2ca358ba4dce364',''),
}
for name,(digest,prefix) in cases.items():
    sample=(root/(name+'.dex')).read_bytes()
    assert hashlib.sha256(sample).hexdigest()==digest
    assert sample[:8]==b'dex\n035\0' and sample[12:32]==hashlib.sha1(sample[32:]).digest()
    assert struct.unpack_from('<I',sample,8)[0]==zlib.adler32(sample[12:]) & 0xffffffff
    size,offset=struct.unpack_from('<II',sample,56); assert size==8
    raw=[]
    for i in range(size):
        at=struct.unpack_from('<I',sample,offset+4*i)[0]
        length=0
        for shift in range(0,35,7):
            byte=sample[at];at+=1;length|=(byte&127)<<shift
            if not byte&128:break
        else:raise AssertionError('invalid ULEB')
        end=sample.index(0,at);raw.append((length,sample[at:end]))
    target=(2048,b'x'*2048) if name=='long' else ((5,bytes.fromhex(prefix)) if name=='endnul' else (8,bytes.fromhex(prefix)+b'leading'))
    assert raw.count(target)==1
    if name=='long':assert raw[6]==target
print('PASS fixed DEX SHA, checksum, eight string IDs and MUTF-8 bytes')
