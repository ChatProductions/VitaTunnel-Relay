#!/usr/bin/env python3
"""Build the final r11 FILEIO reply-size correction from the public r10 VPK.

Hardware r10 logs prove a FILEIO RPC reply-size guard rejected 8 bytes where
the native service accepted exactly 4. This bounded Thumb-2 correction:
  * restores the ordinary r10 error-reporting path (no telemetry remap);
  * accepts exactly 4 or 8 at both FILEIO size guards;
  * preserves all other client, server, mode, semaphore and operation checks;
  * changes no game ELF, game data, IOPRP or packaging resources.

The existing compiled reply writer returns its 32-bit operation result;
the 8-byte buffer's second word is not initialized by this binary-only patch.
The AstraRecompish source-side implementation is more complete and also
zero-fills that word. r11 is experimental, not proof of playable gameplay.
"""

import argparse
import hashlib
import io
import pathlib
import struct
import zipfile
import zlib

import zopfli.zlib

SOURCE_SHA = "2ef2b99979b0b32e66ccb15ef3a96043b664736838a1dba8305bdc5f39e39bb5"
TITLE_ID = "NFMRA0001"
VERSION = "game-nfsmw-aot-20261029-fileio-reply-r11"
FILENAME = "NFSMW11_AOT_FILEIO8_20261029.vpk"
OLD_MARKER = b"nfsmw-aot-20261029-trace-r10"
NEW_MARKER = b"nfsmw-aot-20261029-reply-r11"

# ARM text offsets and bytes verified against the published r10 FSELF.
OUTER_OFFSET = 0x1C01F8
EXPECTED_OUTER = bytes.fromhex("04 2b 17 d1")
OUTER_HOOK = bytes.fromhex("1b f0 16 b8")  # B.W 0x1DB228

INNER_OFFSET = 0x1BF5FE
EXPECTED_INNER = bytes.fromhex("04 3c 18 bf 01 24")
INNER_HOOK = bytes.fromhex("1b f0 8d bf 00 bf")  # B.W 0x1DB51C; NOP

R10_TRACE_OFFSET = 0x1C022C
EXPECTED_R10_TRACE = bytes.fromhex("1b f0 76 b9")
RESTORED_REJECT = bytes.fromhex("df ed 34 0b")  # original VFP error-state store
ORIGINAL_R10_TRACE = bytes.fromhex(
    "c7f8a851 d7f88430 c7f8ac31 049b c7f89030 "
    "059b c7f89430 039b c7f89830 e4f7abbb"
)

OUTER_CAVE = 0x1DB228
OUTER_CAVE_SIZE = 24
# cmp r3,#4; beq success; cmp r3,#8; bne reject;
# success: b.w 0x1C01FC; reject: b.w 0x1C022C.
OUTER_STUB = bytes.fromhex("04 2b 01 d0 08 2b 01 d1 e4 f7 e4 bf e4 f7 fa bf")

INNER_CAVE = 0x1DB51C
INNER_CAVE_SIZE = 36
# cmp r4,#4; beq good; cmp r4,#8; bne bad;
# good: movs r4,#0; b.w 0x1BF604;
# bad:  movs r4,#1; b.w 0x1BF604.
INNER_STUB = bytes.fromhex("04 2c 01 d0 08 2c 02 d1 00 24 e4 f7 6d b8 01 24 e4 f7 6a b8")

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
    start, _old_len, next_start, decoded = unpack_text(eboot)
    checks = (
        (OUTER_OFFSET, EXPECTED_OUTER, "outer FILEIO reply guard"),
        (INNER_OFFSET, EXPECTED_INNER, "inner FILEIO reply guard"),
        (R10_TRACE_OFFSET, EXPECTED_R10_TRACE, "r10 trace branch"),
        (OUTER_CAVE, b"\0" * OUTER_CAVE_SIZE, "unused outer alignment cave"),
        (INNER_CAVE, ORIGINAL_R10_TRACE + b"\0" * (INNER_CAVE_SIZE - len(ORIGINAL_R10_TRACE)),
         "r10 trace cave"),
    )
    for offset, expected, label in checks:
        if decoded[offset:offset + len(expected)] != expected:
            raise ValueError("unexpected r10 executable at " + label)
    if decoded.count(OLD_MARKER) != 1 or len(OLD_MARKER) != len(NEW_MARKER):
        raise ValueError("wrong build marker or mismatched marker lengths")
    if len(OUTER_STUB) > OUTER_CAVE_SIZE or len(INNER_STUB) > INNER_CAVE_SIZE:
        raise ValueError("invalid alignment stub length")

    text = bytearray(decoded)
    text[OUTER_OFFSET:OUTER_OFFSET + len(OUTER_HOOK)] = OUTER_HOOK
    text[INNER_OFFSET:INNER_OFFSET + len(INNER_HOOK)] = INNER_HOOK
    text[R10_TRACE_OFFSET:R10_TRACE_OFFSET + 4] = RESTORED_REJECT
    text[OUTER_CAVE:OUTER_CAVE + OUTER_CAVE_SIZE] = (
        OUTER_STUB + b"\0" * (OUTER_CAVE_SIZE - len(OUTER_STUB)))
    text[INNER_CAVE:INNER_CAVE + INNER_CAVE_SIZE] = (
        INNER_STUB + b"\0" * (INNER_CAVE_SIZE - len(INNER_STUB)))
    at = text.index(OLD_MARKER)
    text[at:at + len(OLD_MARKER)] = NEW_MARKER

    packed = zopfli.zlib.compress(bytes(text), numiterations=3)
    if len(packed) > next_start - start or len(packed) < 100000:
        raise ValueError("patched text cannot fit the original FSELF segment")
    result = bytearray(eboot)
    result[start:next_start] = packed + b"\0" * (next_start - start - len(packed))
    struct.pack_into("<Q", result, 0x148, len(packed))
    if len(result) != len(eboot):
        raise ValueError("unexpected FSELF size change")
    _, _, checked_next, unpacked = unpack_text(result)
    if checked_next != next_start or unpacked != text:
        raise ValueError("patched FSELF failed decompression validation")
    return bytes(result)


def make_vpk(blob):
    if hash_of(blob) != SOURCE_SHA:
        raise ValueError("input does not match the verified public r10 VPK")
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
        if NEW_MARKER not in text:
            raise ValueError("missing r11 build marker")
        for offset, expected in (
            (OUTER_OFFSET, OUTER_HOOK),
            (INNER_OFFSET, INNER_HOOK),
            (R10_TRACE_OFFSET, RESTORED_REJECT),
            (OUTER_CAVE, OUTER_STUB),
            (INNER_CAVE, INNER_STUB),
        ):
            if text[offset:offset + len(expected)] != expected:
                raise ValueError("r11 executable patch failed verification")
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
