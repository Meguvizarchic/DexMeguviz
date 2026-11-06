"""Check pinned DEX bytes used as the independent SQL site oracle."""
import argparse
import hashlib
import struct
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--fixtures',required=True,type=Path)
args=parser.parse_args()
fixtures={
 'method_facts/method-uses.dex':('8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc',(26,10,113,4,0,96,0,14)),
 'use_relations/two-invokes.dex':('04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b',(113,4,0,113,4,0,0,14)),
 'use_relations/field-read-write.dex':('7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d',(96,0,103,0,0,0,0,14)),
 'use_relations/string-normal-jumbo.dex':('65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04',(26,10,27,10,0,0,0,14)),
 'method_facts/invoke-domains-038.dex':('ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0',(0x10fa,4,0,0,0xfc,0,0,14)),
 'use_relations/valid-then-corrupt.dex':('4e0661d233cfc3eaf32aff66e615a1cacba822e768c3c3b4559f0f0abfc2c2be',(26,10,113,4,0,115,0,14)),
}
for name,(digest,words) in fixtures.items():
    raw=(args.fixtures/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==digest,name
    assert raw[:4]==b'dex\n' and struct.unpack_from('<I',raw,416+12)[0]==8,name
    assert struct.unpack_from('<8H',raw,416+16)==words,name
print('PASS six fixed DEX identities and instruction words; no ART verification')
