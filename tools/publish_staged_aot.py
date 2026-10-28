#!/usr/bin/env python3
"""Publish an explicitly staged NFSMW AOT VPK without storing the private ELF."""
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import struct
import subprocess
import zipfile

REPOSITORY = os.environ["GITHUB_REPOSITORY"]
REQUEST = pathlib.Path("relay/release-request.json")
MANIFEST = pathlib.Path("tunnel/manifest.txt")


def required_string(request, key, expression):
    value = request.get(key)
    if not isinstance(value, str) or not re.fullmatch(expression, value):
        raise ValueError(f"invalid {key}")
    return value


def embedded_title_id(vpk):
    with zipfile.ZipFile(io.BytesIO(vpk)) as archive:
        members = archive.namelist()
        if "sce_sys/param.sfo" not in members or "eboot.bin" not in members:
            raise ValueError("not a complete Vita VPK")
        if any(name.lower().endswith("/boot.elf") or name.lower() == "boot.elf"
               for name in members):
            raise ValueError("private guest ELF must never be published")
        sfo = archive.read("sce_sys/param.sfo")
    if len(sfo) < 20:
        raise ValueError("truncated SFO header")
    magic, _, keys, data, count = struct.unpack_from("<IIIII", sfo)
    if magic != 0x46535000 or count > 128 or 20 + count * 16 > len(sfo):
        raise ValueError("invalid SFO header")
    for i in range(count):
        key_offset, _, length, maximum, data_offset = struct.unpack_from(
            "<HHIII", sfo, 20 + i * 16)
        key_start = keys + key_offset
        value_start = data + data_offset
        if key_start >= len(sfo) or value_start > len(sfo):
            raise ValueError("SFO offset outside file")
        key_end = sfo.find(b"\\x00", key_start)
        if key_end < 0:
            raise ValueError("unterminated SFO key")
        if sfo[key_start:key_end] == b"TITLE_ID":
            if length > maximum or value_start + length > len(sfo):
                raise ValueError("invalid SFO title field")
            return sfo[value_start:value_start + length].rstrip(b"\\x00").decode("ascii")
    raise ValueError("SFO has no TITLE_ID")


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if request.get("title_id") != "NFMRA0001":
        raise ValueError("wrong target title")
    tag = required_string(request, "tag", r"game-[a-zA-Z0-9_.-]{1,42}")
    filename = required_string(request, "filename", r"[A-Za-z0-9_.-]+\\.vpk")
    expected = required_string(request, "sha256", r"[0-9a-f]{64}")
    blob_sha = required_string(request, "blob_sha", r"[0-9a-f]{40}")

    # A Git blob is a staging object, not an ELF source commit. The only public
    # download is the validated .vpk attached to the GitHub Release.
    response = subprocess.check_output(
        ["gh", "api", f"repos/{REPOSITORY}/git/blobs/{blob_sha}"])
    blob = json.loads(response)
    if blob.get("encoding") != "base64":
        raise ValueError("staged blob encoding mismatch")
    raw = base64.b64decode(blob["content"], validate=False)
    if not 100000 <= len(raw) <= 40000000:
        raise ValueError("VPK size outside expected limits")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise ValueError("staged VPK SHA256 does not match request")
    actual_title = embedded_title_id(raw)
    if actual_title != "NFMRA0001":
        raise ValueError(f"wrong embedded Vita TITLE_ID: {actual_title}")

    staging = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / filename
    staging.write_bytes(raw)
    subprocess.run(
        ["gh", "release", "create", tag, str(staging),
         "--repo", REPOSITORY, "--title", "NFSMW 2005 AOT Test (OSD syscall)",
         "--notes", "Experimental NFSMW-specific native AOT test VPK. Requires user-supplied ux0:data/ps2vita/boot.elf. Get/SetOsdConfigParam startup syscall fixes; not a playable port."],
        check=True)
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{filename}"
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        f"version={tag}\\ntitle_id=NFMRA0001\\nvpk_url={url}\\nsha256={digest}\\n",
        encoding="ascii")
    print(f"Published validated {actual_title} VPK ({len(raw)} bytes) and manifest.")


if __name__ == "__main__":
    main()
