"""Manually specified v5 bytes for a root expand of the default method scan.

No production encoder is imported. Fields are documented in ADR-0008 and the
stage implementation; the fixed hexadecimal byte string is the golden vector.
"""
import hashlib
import struct

u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
words=lambda *values:b''.join(u32(v) for v in values)
frame=lambda data:u64(len(data))+data
predicate=words(0,0,0,0,0xffffffff,0)
scan=words(0,0,1)+frame(predicate)+words(0,1,0xffffffff,1,0,0,0,0,0,0)
expand=words(8,0,0,0,1,0xffffffff,1,0,0,0)
expand+=words(0,0,0,0,0,1,2)+u64(100000)*3+words(0,0,0,0,1)+frame(scan)
top=words(0,0,4096)+u64(100000000)+words(7,1,0,8771,1,100000,0,0)
canonical=b'DexMeguviz:QueryIR:expand-v5'+top+expand
expected_hex=('4465784d65677576697a3a517565727949523a657870616e642d763500000000000000000010000000e1f505000000000700000001000000000000004322000001000000a086010000000000000000000800000000000000000000000000000001000000ffffffff0100000000000000000000000000000000000000000000000000000000000000000000000100000002000000a086010000000000a086010000000000a08601000000000000000000000000000000000000000000010000005400000000000000000000000000000001000000180000000000000000000000000000000000000000000000ffffffff000000000000000001000000ffffffff01000000000000000000000000000000000000000000000000000000')
expected_hash='3bfd47f1ef95bf8167c954a743f47cd418a26b65180d9a1864805498fcae288b'
assert len(canonical)==284 and canonical.hex()==expected_hex
assert hashlib.sha256(canonical).hexdigest()==expected_hash
print('query:v5:'+expected_hash)
