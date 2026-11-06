"""Cross-check fixed MUTF bytes against the independent Python DEX reader."""
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
EXPECTED = {
    'lone-high.dex': ([0xd800], '01eda08000', '899e41549066618ec3e22e39d82c1aa05d0c8425803cf71eb6cd4c20a3c4fc53'),
    'lone-low.dex': ([0xdc00], '01edb08000', 'f71f969b8f96b9a9dbc158088fd579fe96e4d7cdb0d24cf3a12dfb92fe8d1ab7'),
    'mixed-unpaired.dex': ([0xd800,0x78,0xdc00,0,0xd83d,0xde00], '06eda08078edb080c080eda0bdedb88000', '72d11067710b37251f62b5d065656f47161e2a93597bade43562643b3d94bbe3'),
}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--oracle',type=Path,required=True)
    ap.add_argument('--fixtures',type=Path,required=True)
    args=ap.parse_args()
    spec=importlib.util.spec_from_file_location('independent_dex_oracle',args.oracle)
    oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    observations={}
    for name,(units,raw_hex,digest) in EXPECTED.items():
        image=(args.fixtures/name).read_bytes()
        if hashlib.sha256(image).hexdigest()!=digest:raise AssertionError('unexpected fixture identity: '+name)
        parsed=oracle.parse_dex(image)
        actual=[list(oracle.utf16_units(s)) for s in parsed['strings']]
        if actual.count(units)!=1:raise AssertionError('independent UTF-16 decode mismatch: '+name)
        count,offset=struct.unpack_from('<II',image,56)
        starts=[struct.unpack_from('<I',image,offset+i*4)[0] for i in range(count)]
        raw=bytes.fromhex(raw_hex)
        matches=[i for i in starts if image[i:i+len(raw)]==raw]
        if len(matches)!=1:raise AssertionError('fixed MUTF does not begin at exactly one string ID: '+name)
        observations[name]={'sha256':digest,'units':units,'string_data_offset':matches[0]}
    print(json.dumps({'passed':len(observations),'scope':'generated DEX UTF-16 and independent raw MUTF comparison; no ART runtime claim','observations':observations}))

if __name__=='__main__':main()
