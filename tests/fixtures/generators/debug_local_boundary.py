"""Authored DEX local boundary fixture; output exclusively created, no cleanup."""
from pathlib import Path
import argparse,hashlib,struct,zlib

def build_double(parameters):
    # A separate authored 035 DEX: static m(D)V has two incoming words but one parameter.
    names = sorted(('D', 'Ldouble/Test;', 'Ljava/lang/Object;', 'V', 'VD', 'm'))
    strings = {name: i for i, name in enumerate(names)}
    descriptors = sorted(('D', 'Ldouble/Test;', 'Ljava/lang/Object;', 'V'), key=strings.__getitem__)
    types = {name: i for i, name in enumerate(descriptors)}
    data = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind, count, width):
        at = len(data); data.extend(bytes(count * width)); sections.append((kind, count, at)); return at

    def leb(value):
        result = bytearray()
        while True:
            byte = value & 127; value >>= 7; result.append(byte | (128 if value else 0))
            if not value: return bytes(result)

    string_at = table(1, len(names), 4)
    type_at = table(2, len(descriptors), 4)
    proto_at = table(3, 1, 12)
    method_at = table(5, 1, 8)
    class_at = table(6, 1, 32)
    data_at = len(data)
    type_list = len(data); sections.append((0x1001, 1, type_list))
    data.extend(struct.pack('<IH', 1, types['D']))
    sections.append((0x2002, len(names), len(data)))
    for i, name in enumerate(names):
        struct.pack_into('<I', data, string_at + 4 * i, len(data))
        data.extend(leb(len(name)) + name.encode('ascii') + b'\0')
    data.extend(bytes(-len(data) % 4))
    code = len(data); sections.append((0x2001, 1, code))
    data.extend(struct.pack('<HHHHII8H', 2, 2, 0, 0, 0, 8, 0x0013, 1, 0x0300, 1, 1, 0, 0xff, 0x000e))
    class_data = len(data); sections.append((0x2000, 1, class_data))
    data.extend(bytes.fromhex('00 00 01 00 00 09') + leb(code))
    debug = len(data); sections.append((0x2003, 1, debug))
    data.extend(b'\x01' + leb(parameters) + bytes(parameters) + bytes.fromhex('03 00 00 00 01 01 05 00 01 01 06 00 01 01 05 00 01 04 03 00 00 00 01 01 05 00 00'))
    data.extend(bytes(-len(data) % 4))
    map_at = len(data); sections.append((0x1000, 1, map_at))
    data.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sorted(sections, key=lambda item: item[2]):
        data.extend(struct.pack('<HHII', kind, 0, count, offset))
    for i, name in enumerate(descriptors): struct.pack_into('<I', data, type_at + 4 * i, strings[name])
    struct.pack_into('<III', data, proto_at, strings['VD'], types['V'], type_list)
    struct.pack_into('<HHI', data, method_at, types['Ldouble/Test;'], 0, strings['m'])
    struct.pack_into('<8I', data, class_at, types['Ldouble/Test;'], 1, types['Ljava/lang/Object;'],
                     0, 0xffffffff, 0, class_data, 0)
    struct.pack_into('<I', data, code + 8, debug)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<20I', data, 32, len(data), 112, 0x12345678, 0, 0, map_at,
                     len(names), string_at, len(descriptors), type_at, 1, proto_at, 0, 0,
                     1, method_at, 1, class_at, len(data) - data_at, data_at)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return data


if __name__ == '__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();data=build_double(1)
 with a.output.open('xb') as f:f.write(data)
 print('generated',len(data),hashlib.sha256(data).hexdigest())
