#!/usr/bin/env python3
"""Fail-closed integrity audit for a public VitaTunnel game manifest.

Only public VPKs are read. No PS2 ELF, IOPRP, BIOS, or game data are needed.
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct
import sys
from urllib.parse import urlsplit
from urllib.request import urlopen
import zipfile

REPO = "ChatProductions/VitaTunnel-Relay"
MAX_VPK_BYTES = 64 * 1024 * 1024
MAX_SFO_BYTES = 1024 * 1024
VERSION_RE = re.compile(r"[A-Za-z0-9_.-]{1,48}\Z")
TITLE_RE = re.compile(r"[A-Z0-9]{9}\Z")
SHA_RE = re.compile(r"[a-fA-F0-9]{64}\Z")


def fail(message):
    raise ValueError(message)


def parse_manifest(path):
    fields = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail("malformed manifest line")
        key, value = line.split("=", 1)
        if key not in {"version", "title_id", "vpk_url", "sha256"} or key in fields:
            fail("unexpected or repeated manifest key: " + key)
        fields[key] = value
    if set(fields) != {"version", "title_id", "vpk_url", "sha256"}:
        fail("manifest missing required fields")
    if not VERSION_RE.fullmatch(fields["version"]):
        fail("version is not compatible with VitaTunnel's 48-character parser")
    if not TITLE_RE.fullmatch(fields["title_id"]) or fields["title_id"] == "VITATUNN1":
        fail("invalid or reserved title ID")
    if not SHA_RE.fullmatch(fields["sha256"]):
        fail("invalid SHA-256 field")
    return fields


def select_public_package(url, repo_root):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail("package URL must be unmodified HTTPS")
    if parsed.hostname == "raw.githubusercontent.com":
        prefix = f"/{REPO}/main/tunnel/packages/"
        if not parsed.path.startswith(prefix):
            fail("raw package must belong to this repository's main/tunnel/packages")
        name = parsed.path[len(prefix):]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.vpk", name):
            fail("invalid raw package filename")
        package = repo_root / "tunnel" / "packages" / name
        if not package.is_file() or package.is_symlink():
            fail("referenced public package is absent or symlinked")
        return package
    if parsed.hostname == "github.com":
        prefix = f"/{REPO}/releases/download/"
        if not parsed.path.startswith(prefix):
            fail("release package must belong to this repository")
        suffix = parsed.path[len(prefix):].split("/")
        if len(suffix) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in suffix) or not suffix[1].endswith(".vpk"):
            fail("invalid release package URL")
        return None
    fail("unsupported package host")


def download_public_release(url, output):
    with urlopen(url, timeout=35) as response, output.open("wb") as target:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_VPK_BYTES:
                fail("release package exceeds 64 MiB audit limit")
            target.write(chunk)
    return output


def parse_sfo_title(sfo):
    if len(sfo) < 20 or len(sfo) > MAX_SFO_BYTES:
        fail("missing or invalid param.sfo")
    magic, version, key_table, data_table, count = struct.unpack_from("<4sIIII", sfo)
    if magic != b"\x00PSF" or count > 1024 or 20 + count * 16 > len(sfo):
        fail("invalid SFO header/index bounds")
    if key_table >= len(sfo) or data_table >= len(sfo):
        fail("invalid SFO table offsets")
    for i in range(count):
        key_offset, fmt, length, maximum, value_offset = struct.unpack_from("<HHIII", sfo, 20 + i * 16)
        key_at = key_table + key_offset
        value_at = data_table + value_offset
        if key_at >= len(sfo) or length > maximum or value_at > len(sfo) or length > len(sfo) - value_at:
            fail("SFO entry exceeds bounds")
        key_end = sfo.find(b"\x00", key_at)
        if key_end < 0:
            fail("unterminated SFO key")
        if sfo[key_at:key_end] == b"TITLE_ID":
            try:
                return sfo[value_at:value_at + length].split(b"\x00", 1)[0].decode("ascii")
            except UnicodeDecodeError:
                fail("invalid TITLE_ID encoding")
    fail("VPK param.sfo has no TITLE_ID")


def audit(package, expected_sha, expected_title):
    if package.stat().st_size > MAX_VPK_BYTES:
        fail("VPK exceeds audit size limit")
    sha = hashlib.sha256()
    with package.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
    if sha.hexdigest().lower() != expected_sha.lower():
        fail(f"VPK SHA-256 mismatch (actual {sha.hexdigest()})")
    with zipfile.ZipFile(package) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            fail("VPK has duplicate ZIP members")
        for name in names:
            parts = name.replace("\\", "/").split("/")
            if name.startswith("/") or any(p in ("", ".", "..") for p in parts if not (p == "" and name.endswith("/"))):
                fail("unsafe VPK member path")
            if any(p.lower() in {"boot.elf", "ioprp280.img", "bios.bin", "slus_213.51"} for p in parts):
                fail("private game/firmware asset in public VPK")
        if "eboot.bin" not in names or "sce_sys/param.sfo" not in names:
            fail("VPK missing eboot.bin or sce_sys/param.sfo")
        info = z.getinfo("sce_sys/param.sfo")
        if info.file_size > MAX_SFO_BYTES:
            fail("oversized param.sfo")
        title = parse_sfo_title(z.read(info))
        if title != expected_title:
            fail(f"embedded VPK title {title!r} != manifest {expected_title!r}")
    return sha.hexdigest(), title


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = parse_manifest(root / "tunnel" / "manifest.txt")
    package = select_public_package(manifest["vpk_url"], root)
    if package is None:
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            package = download_public_release(manifest["vpk_url"], Path(temp) / "release.vpk")
            digest, title = audit(package, manifest["sha256"], manifest["title_id"])
    else:
        digest, title = audit(package, manifest["sha256"], manifest["title_id"])
    print(f"PASS: {manifest['version']} title={title} sha256={digest} (public VPK integrity only; no gameplay claim)")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
