#!/usr/bin/env python3
"""Patch the known public r7 Vita VPK to support blocking SIF RPC calls.

Only the already compiled Vita executable is changed. The private PS2 ELF,
IOPRP image and disc files are never opened or packaged.
"""
import argparse
import hashlib
import io
import pathlib
import struct
import zipfile
import zlib

SOURCE_SHA = "2eaaf7dadbc909e7b6e1c7165a13af4ef66a72f2693aa32fb35af7d4d6f42985"
R7_MARKER = b"nfsmw-aot-20261029-fileio-r7"
R8_MARKER = b"nfsmw-aot-20261029-fileio-r8"
OFFSET = 0x1C01FC
ORIGINAL = bytes.fromhex("04 9b 01 2b 14 d1 1c 22")
PATCHED = bytes.fromhex("04 9b 01 2b 14 d8 1c 22")
FILENAME = "NFSMW08_AOT_RPC_CALL_20261029.vpk"
VERSION = "game-nfsmw-aot-20261029-rpc-call-r8"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def title_id(sfo):
    magic, _, keys, data, count = struct.unpack_from("<IIIII", sfo)
    if magic != 0x46535000 or count > 128 or 20 + count * 16 > len(sfo):
        raise ValueError("invalid SFO")
    for n in range(count):
        ko, _, used, limit, off = struct.unpack_from("<HHIII", sfo, 20 + n * 16)
        start, value = keys + ko, data + off
        if start >= len(sfo) or used > limit or value + used > len(sfo):
            raise ValueError("invalid SFO offsets")
        end = sfo.find(b"\0", start)
        if end < 0:
            raise ValueError("invalid SFO key")
        if sfo[start:end] == b"TITLE_ID":
            return sfo[value:value + used].rstrip(b"\0").decode("ascii")
    raise ValueError("missing TITLE_ID")


def unpack_text(eboot):
    if eboot[:4] != b"SCE\0":
        raise ValueError("invalid Vita FSELF")
    start, size = struct.unpack_from("<QQ", eboot, 0x140)
    if start != 0x1000 or size <= 0 or start + size > len(eboot):
        raise ValueError("unknown FSELF layout")
    text = zlib.decompress(eboot[start:start + size])
    if len(text) != 0x204FD0:
        raise ValueError("unknown ARM segment size")
    return start, size, text


def patch_eboot(eboot):
    start, size, original = unpack_text(eboot)
    if original[OFFSET:OFFSET + len(ORIGINAL)] != ORIGINAL:
        raise ValueError("r7 instruction mismatch")
    if original.count(R7_MARKER) != 1:
        raise ValueError("r7 build identifier mismatch")
    text = bytearray(original)
    text[OFFSET:OFFSET + len(PATCHED)] = PATCHED
    marker = text.index(R7_MARKER)
    text[marker:marker + len(R7_MARKER)] = R8_MARKER
    compressed = zlib.compress(text, 9)
    if len(compressed) != size:
        raise ValueError("FSELF compressed-size change: refusing unsafe repack")
    new = bytearray(eboot)
    new[start:start + size] = compressed
    _, _, verified = unpack_text(new)
    if verified != text:
        raise ValueError("post-patch verification failed")
    return bytes(new)


def make_vpk(blob):
    if sha(blob) != SOURCE_SHA:
        raise ValueError("source r7 SHA-256 mismatch")
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as source, zipfile.ZipFile(out, "w") as target:
        names = source.namelist()
        if "eboot.bin" not in names or "sce_sys/param.sfo" not in names:
            raise ValueError("incomplete Vita VPK")
        if any(n.lower().endswith("boot.elf") for n in names):
            raise ValueError("private ELF must never be published")
        if title_id(source.read("sce_sys/param.sfo")) != "NFMRA0001":
            raise ValueError("wrong Vita TITLE_ID")
        for entry in source.infolist():
            data = source.read(entry.filename)
            target.writestr(entry, patch_eboot(data) if entry.filename == "eboot.bin" else data)
    result = out.getvalue()
    with zipfile.ZipFile(io.BytesIO(result)) as check:
        if check.testzip() is not None:
            raise ValueError("bad output ZIP checksum")
        _, _, text = unpack_text(check.read("eboot.bin"))
        if R8_MARKER not in text or text[OFFSET:OFFSET + len(PATCHED)] != PATCHED:
            raise ValueError("patch missing from output")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    a = parser.parse_args()
    result = make_vpk(a.source.read_bytes())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_bytes(result)
    digest = sha(result)
    if a.manifest:
        url = "https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/" + FILENAME
        a.manifest.parent.mkdir(parents=True, exist_ok=True)
        a.manifest.write_text(f"version={VERSION}\ntitle_id=NFMRA0001\nvpk_url={url}\nsha256={digest}\n", encoding="ascii")
    print(f"Verified {VERSION}: {len(result)} bytes SHA256={digest}")


if __name__ == "__main__":
    main()
