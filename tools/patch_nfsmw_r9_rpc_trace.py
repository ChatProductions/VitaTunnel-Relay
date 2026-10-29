#!/usr/bin/env python3
"""Build an r9 diagnostic VPK from the exact published r8 binary.

The first rejected SIF RPC_CALL stores five packet fields in existing fault
report slots. This preserves the game's actual failure behavior and avoids
guessing or fabricating PS2 file-service responses. Interpretation for r9 ONLY:

  native_iop_unknown_cid = RPC client pointer
  native_iop_unknown_sid = bound FILEIO client pointer
  fileio_last_fno       = RPC mode
  fileio_last_result    = RPC server handle
  fileio_bytes_read     = RPC receive-buffer size

All other builds keep the ordinary meaning of those fields. Neither the
private boot.elf nor IOPRP280.IMG is read, changed, or included.
"""

import argparse
import hashlib
import io
import pathlib
import struct
import zipfile
import zlib

import zopfli.zlib

SOURCE_SHA = "d7393ba4dafd7f12e0fb6e97383e6a6a6b6e8e9a3182dad6e1ae86c8bdd5fde7"
TITLE_ID = "NFMRA0001"
VERSION = "game-nfsmw-aot-20261029-rpc-trace-r9"
FILENAME = "NFSMW09_AOT_RPCTRACE_20261029.vpk"
OLD_MARKER = b"nfsmw-aot-20261029-fileio-r8"
NEW_MARKER = b"nfsmw-aot-20261029-fileio-r9"

# Thumb-2 B.W to the verified 36-byte alignment cave after a return.
HANDLER_OFFSET = 0x1C01B8
EXPECTED_HANDLER = bytes.fromhex("0a 23 c8 f2 00 03 c7 f8 a8 31")
HOOK_BRANCH = bytes.fromhex("1b f0 b0 b9")
CAVE_OFFSET = 0x1DB51C
CAVE_LENGTH = 36
# Thumb-2 instructions; built and checked against address-specific assembly:
# str.w r5,[r7,#0x1a8]; ldr.w r3,[r7,#0x84];
# str.w r3,[r7,#0x1ac]; ldr r3,[sp,#0x10];
# str.w r3,[r7,#0x90]; ldr r3,[sp,#0x14];
# str.w r3,[r7,#0x94]; ldr r3,[sp,#0xc];
# str.w r3,[r7,#0x98]; b.w #0x1bfc94 (original failure return).
CAVE_STUB = bytes.fromhex(
    "c7f8a851 d7f88430 c7f8ac31 049b c7f89030 "
    "059b c7f89430 039b c7f89830 e4f7abbb"
)


def hash_of(data):
    return hashlib.sha256(data).hexdigest()


def get_title_id(sfo):
    magic, _, keys, data, count = struct.unpack_from("<IIIII", sfo)
    if magic != 0x46535000 or count > 128 or 20 + count * 16 > len(sfo):
        raise ValueError("invalid Vita SFO")
    for i in range(count):
        key_off, _, used, limit, val_off = struct.unpack_from("<HHIII", sfo, 20 + 16 * i)
        k, v = keys + key_off, data + val_off
        if k >= len(sfo) or used > limit or v + used > len(sfo):
            raise ValueError("invalid SFO offsets")
        end = sfo.find(b"\0", k)
        if end < 0:
            raise ValueError("invalid SFO key")
        if sfo[k:end] == b"TITLE_ID":
            return sfo[v:v + used].rstrip(b"\0").decode("ascii")
    raise ValueError("Vita SFO lacks TITLE_ID")


def unpack_text(eboot):
    if eboot[:4] != b"SCE\0":
        raise ValueError("not a Vita FSELF")
    offset, size = struct.unpack_from("<QQ", eboot, 0x140)
    next_offset, next_size = struct.unpack_from("<QQ", eboot, 0x160)
    if offset != 0x1000 or next_offset != 0xD87B0 or not 0 < size <= next_offset - offset:
        raise ValueError("unexpected Vita executable segment layout")
    text = zlib.decompress(eboot[offset:offset + size])
    if len(text) != 0x204FD0 or not 0 < next_size < len(eboot) - next_offset:
        raise ValueError("invalid Vita executable segments")
    return offset, size, next_offset, text


def patch_eboot(eboot):
    start, old_len, next_start, decoded = unpack_text(eboot)
    if decoded[HANDLER_OFFSET:HANDLER_OFFSET + len(EXPECTED_HANDLER)] != EXPECTED_HANDLER:
        raise ValueError("r8 reject handler mismatch")
    if decoded[CAVE_OFFSET:CAVE_OFFSET + CAVE_LENGTH] != b"\0" * CAVE_LENGTH:
        raise ValueError("expected safe alignment cave absent")
    if decoded.count(OLD_MARKER) != 1 or len(CAVE_STUB) > CAVE_LENGTH:
        raise ValueError("wrong source build or invalid trace stub")
    text = bytearray(decoded)
    text[HANDLER_OFFSET:HANDLER_OFFSET + len(HOOK_BRANCH)] = HOOK_BRANCH
    text[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_STUB)] = CAVE_STUB
    at = text.index(OLD_MARKER)
    text[at:at + len(OLD_MARKER)] = NEW_MARKER

    packed = zopfli.zlib.compress(bytes(text), numiterations=3)
    # Keep all physical segment offsets and the complete FSELF size unchanged.
    # The compressed segment's explicit size points to its actual zlib stream.
    if len(packed) > old_len or len(packed) < 100000:
        raise ValueError("compressed ARM text would not fit the existing FSELF segment")
    result = bytearray(eboot)
    result[start:next_start] = packed + b"\0" * (next_start - start - len(packed))
    struct.pack_into("<Q", result, 0x148, len(packed))
    if len(result) != len(eboot):
        raise ValueError("unexpected FSELF size change")
    _, _, checked_next, unpacked = unpack_text(result)
    if checked_next != next_start or unpacked != text:
        raise ValueError("patched FSELF failed decompression verification")
    return bytes(result)


def make_vpk(blob):
    if hash_of(blob) != SOURCE_SHA:
        raise ValueError("input does not match the verified public r8 VPK")
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as original, zipfile.ZipFile(output, "w") as out:
        members = original.namelist()
        if "eboot.bin" not in members or "sce_sys/param.sfo" not in members:
            raise ValueError("not a complete Vita package")
        if get_title_id(original.read("sce_sys/param.sfo")) != TITLE_ID:
            raise ValueError("wrong embedded Vita TITLE_ID")
        if any(name.lower().endswith("boot.elf") for name in members):
            raise ValueError("private PS2 ELF must not be distributed")
        for info in original.infolist():
            data = original.read(info.filename)
            out.writestr(info, patch_eboot(data) if info.filename == "eboot.bin" else data)
    result = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(result)) as check:
        if check.testzip() is not None:
            raise ValueError("invalid output archive")
        _, _, _, text = unpack_text(check.read("eboot.bin"))
        if NEW_MARKER not in text or text[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_STUB)] != CAVE_STUB:
            raise ValueError("missing diagnostic code in output")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=pathlib.Path)
    ap.add_argument("output", type=pathlib.Path)
    ap.add_argument("--manifest", type=pathlib.Path)
    args = ap.parse_args()
    vpk = make_vpk(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(vpk)
    digest = hash_of(vpk)
    if args.manifest:
        url = "https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/" + FILENAME
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            f"version={VERSION}\ntitle_id={TITLE_ID}\nvpk_url={url}\nsha256={digest}\n", encoding="ascii")
    print(f"Verified {VERSION}: {len(vpk)} bytes SHA256={digest}")


if __name__ == "__main__":
    main()
