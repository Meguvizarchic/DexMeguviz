"""Conservative, bounded APK entry reader for independent metadata verification."""
from __future__ import annotations
from io import BytesIO
import re
import struct
import zipfile
import zlib

class Unsupported(ValueError):
    status = 'Unsupported'
class Budget(ValueError):
    status = 'BudgetExceeded'

def need(condition, message):
    if not condition:
        raise ValueError(message)

def entries(data, allow_empty, remaining_bytes, remaining_sources):
    # Admit only ordinary single-disk ZIP with bounded EOCD and directory; no
    # extraction to disk. ZIP64 and data descriptors are conservatively rejected.
    signature=b'PK\x05\x06'
    minimum=max(0,len(data)-65557)
    pos=data.rfind(signature,minimum)
    while pos>=minimum:
        if pos+22<=len(data):
            disk,cd_disk,on_disk,total,cd_size,cd_offset,comment=struct.unpack_from('<HHHHIIH',data,pos+4)
            if pos+22+comment==len(data):break
        pos=data.rfind(signature,minimum,pos)
    need(pos>=minimum and pos+22<=len(data),'ZIP end record absent')
    if (disk,cd_disk)!=(0,0) or on_disk!=total:
        raise Unsupported('multi-disk ZIP is unsupported')
    if total==0xffff or cd_size==0xffffffff or cd_offset==0xffffffff:
        raise Unsupported('ZIP64 is unsupported by independent verifier')
    if total>4096 or cd_size>4*1024*1024:
        raise Budget('APK directory limit')
    need(cd_offset+cd_size==pos,'ZIP central directory extent')
    try:
        with zipfile.ZipFile(BytesIO(data),'r') as archive:
            all_entries=archive.infolist()
            need(len(all_entries)==total,'ZIP entry count mismatch')
            names=set(); selected=[]; names_bytes=0
            for index,info in enumerate(all_entries):
                name=info.orig_filename
                need(name==info.filename and '\0' not in name,'ZIP name contains NUL')
                names_bytes+=len(name.encode('utf-8'))
                if names_bytes>1024*1024:raise Budget('APK name byte limit')
                need(name not in names,'duplicate ZIP entry name');names.add(name)
                if name=='classes.dex':ordinal=1
                elif re.fullmatch(r'classes[0-9]+\.dex',name):
                    digits=name[7:-4]
                    need(digits[0]!='0' and int(digits)>=2 and int(digits)<=0xffffffff,'noncanonical classesN.dex')
                    ordinal=int(digits)
                else:continue
                if info.flag_bits & ~0x806 or info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
                    raise Unsupported('ZIP flags or compression method unsupported')
                if info.extract_version>=45 or info.file_size>=0xffffffff or info.compress_size>=0xffffffff:
                    raise Unsupported('ZIP64 entry unsupported')
                if info.file_size>16*1024*1024:raise Budget('APK DEX byte limit')
                off=info.header_offset
                need(off>=0 and off+30<=cd_offset,'ZIP local header range')
                sig,_,flags,method,_,_,crc,compressed,size,nlen,xlen=struct.unpack_from('<IHHHHHIIIHH',data,off)
                need(sig==0x04034b50 and flags==info.flag_bits and method==info.compress_type,'ZIP local header mismatch')
                need((crc,compressed,size)==(info.CRC,info.compress_size,info.file_size),'ZIP local sizes or CRC mismatch')
                start=off+30;end=start+nlen;payload=end+xlen
                need(payload<=cd_offset and compressed<=cd_offset-payload,'ZIP local payload range')
                local_name=data[start:end].decode('utf-8' if flags&0x800 else 'cp437')
                need(local_name==name,'ZIP local name mismatch')
                selected.append((ordinal,index,info,payload))
            if len(selected)>remaining_sources:raise Budget('logical source count limit')
            if not selected and not allow_empty:raise ValueError('APK code input contains no DEX')
            selected.sort(key=lambda x:x[0]);output=[]; compressed_remaining=64*1024*1024
            for _,index,info,payload in selected:
                if info.file_size>remaining_bytes:raise Budget('aggregate DEX byte limit')
                if info.compress_size>compressed_remaining:raise Budget('aggregate compressed DEX byte limit')
                compressed_remaining-=info.compress_size
                encoded=data[payload:payload+info.compress_size]
                if info.compress_type==zipfile.ZIP_STORED:
                    need(info.compress_size==info.file_size,'stored ZIP length mismatch')
                    dex=encoded
                else:
                    inflater=zlib.decompressobj(-15)
                    dex=inflater.decompress(encoded,info.file_size+1)
                    need(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,'invalid DEFLATE extent')
                need(len(dex)==info.file_size and zlib.crc32(dex)&0xffffffff==info.CRC,'ZIP decompressed length or CRC mismatch')
                remaining_bytes-=len(dex)
                output.append((info.filename,index,dex))
            return output
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError, UnicodeError, struct.error, zlib.error) as error:
        raise ValueError('invalid APK archive') from error
