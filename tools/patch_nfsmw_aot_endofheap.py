#!/usr/bin/env python3
"""Exact-input-only ARM Thumb EndOfHeap hotfix for the NFSMW AOT test VPK.
The original game ELF is never read, copied or published.
"""
import hashlib
import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

SOURCE_SHA="f7d315e4862d0987904b023a591acc6a0a87fa372f2f2f930600074ea9b91161"
OUTPUT_SHA="ddddf0097490b42ad24e2b044a9c6473d714be622d433ab22d09fba8606e6538"
# Assembled Thumb-2 at 0x8100000c. Load SetupHeap boundary (Emulator
# +0x15438), check it exceeds its base, then call the already-linked
# retire_trapped_syscall implementation and return through normal epilogue.
PATCH=bytes.fromhex("""
f50430a8 f8d01438 f8d02434 4291 d90c f5044036
30b8 2200 2300 2601 9600 f1a8fe0d 2800 d001
f1adbb24 f1adbacf
""")

def digest(b):
    return hashlib.sha256(b).hexdigest()

def patch_fself(d):
    assert d[:4]==b"SCE\0" and d[0xa0:0xa4]==b"\x7fELF"
    assert struct.unpack_from("<Q",d,0x20)[0]==len(d)
    segments=[]
    for i in range(3):
        offset,length,mode=struct.unpack_from("<QQQ",d,0x140+i*32)
        assert mode==2 and offset%16==0 and offset+length<=len(d)
        segments.append(zlib.decompress(d[offset:offset+length]))
    assert [len(x) for x in segments]==[0x2022dc,0x12240,0xa7ff4]
    assert len(PATCH)==46
    code=bytearray(segments[0])
    assert code[12:64]==bytes(52), "expected Thumb code cave changed"
    assert struct.unpack_from("<I",code,0x1ad748)[0]==0x811ad5d9
    code[12:58]=PATCH
    struct.pack_into("<I",code,0x1ad748,0x8100000d)
    segments[0]=bytes(code)
    out=bytearray(d[:0x1000])
    for i,plain in enumerate(segments):
        while len(out)%16:out.append(0)
        offset=len(out)
        packed=zlib.compress(plain,9)
        out+=packed
        struct.pack_into("<QQ",out,0x140+i*32,offset,len(packed))
    struct.pack_into("<Q",out,0x20,len(out))
    assert out[0xa0:0x140]==d[0xa0:0x140]
    assert out[0x1c0:0x1000]==d[0x1c0:0x1000]
    for i,expected in enumerate(segments):
        pos,size=struct.unpack_from("<QQ",out,0x140+i*32)
        assert zlib.decompress(out[pos:pos+size])==expected
    return bytes(out)

def main(input_path, output_path):
    src=Path(input_path).read_bytes()
    assert len(src)==1039019 and digest(src)==SOURCE_SHA, "wrong input release"
    with zipfile.ZipFile(io.BytesIO(src)) as z:
        assert z.namelist()==["sce_sys/param.sfo","eboot.bin"]
        sfo=z.read("sce_sys/param.sfo")
        eboot=patch_fself(z.read("eboot.bin"))
        destination=io.BytesIO()
        with zipfile.ZipFile(destination,"w") as dst:
            for info in z.infolist():
                dst.writestr(info,eboot if info.filename=="eboot.bin" else sfo)
    out=destination.getvalue()
    assert digest(out)==OUTPUT_SHA, "hotfix output unexpectedly changed"
    with zipfile.ZipFile(io.BytesIO(out)) as z:
        assert z.namelist()==["sce_sys/param.sfo","eboot.bin"]
        assert z.read("sce_sys/param.sfo")==sfo
        assert z.read("eboot.bin")==eboot
    Path(output_path).write_bytes(out)
    print(f"Verified hotfix SHA256={OUTPUT_SHA} bytes={len(out)}")
if __name__=="__main__":
    main(sys.argv[1],sys.argv[2])
