#!/usr/bin/env python3
"""Synthetic-only tests for the public VPK manifest integrity gate."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit_relay_manifest as audit


def sfo(title="NFMRA0001"):
    key = b"TITLE_ID\x00"
    value = title.encode("ascii") + b"\x00"
    return (struct.pack("<4sIIII", b"\x00PSF", 0x101, 36, 36 + len(key), 1) +
            struct.pack("<HHIII", 0, 0x204, len(value), len(value), 0) + key + value)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg_dir = self.root / "tunnel" / "packages"
        self.pkg_dir.mkdir(parents=True)
        self.package = self.pkg_dir / "synthetic.vpk"
        self.write_vpk()

    def write_vpk(self, title="NFMRA0001", extra=None):
        with zipfile.ZipFile(self.package, "w") as z:
            z.writestr("eboot.bin", b"synthetic-code-not-a-game")
            z.writestr("sce_sys/param.sfo", sfo(title))
            if extra:
                z.writestr(extra, b"must-not-publish")
        self.sha = hashlib.sha256(self.package.read_bytes()).hexdigest()

    def test_valid_manifest_and_vpk(self):
        self.assertEqual(audit.audit(self.package, self.sha, "NFMRA0001")[1], "NFMRA0001")

    def test_bad_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            audit.audit(self.package, "0" * 64, "NFMRA0001")

    def test_wrong_embedded_title_is_rejected(self):
        self.write_vpk(title="OTHER0001")
        with self.assertRaisesRegex(ValueError, "embedded VPK title"):
            audit.audit(self.package, self.sha, "NFMRA0001")

    def test_private_asset_is_rejected(self):
        self.write_vpk(extra="NFS/IOPRP280.IMG")
        with self.assertRaisesRegex(ValueError, "private game/firmware asset"):
            audit.audit(self.package, self.sha, "NFMRA0001")

    def test_path_traversal_is_rejected(self):
        self.write_vpk(extra="../boot.elf")
        with self.assertRaisesRegex(ValueError, "unsafe VPK member path"):
            audit.audit(self.package, self.sha, "NFMRA0001")

    def test_manifest_parser_rejects_overlong_version(self):
        path = self.root / "tunnel" / "manifest.txt"
        path.write_text("version=" + "x" * 49 + "\ntitle_id=NFMRA0001\nvpk_url=" +
                        "https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/synthetic.vpk\n" +
                        "sha256=" + self.sha + "\n")
        with self.assertRaisesRegex(ValueError, "48-character"):
            audit.parse_manifest(path)

    def test_manifest_url_must_match_relay_repo(self):
        with self.assertRaisesRegex(ValueError, "this repository"):
            audit.select_public_package(
                "https://raw.githubusercontent.com/attacker/repo/main/tunnel/packages/synthetic.vpk", self.root)

    def test_manifest_raw_package_path_is_local(self):
        path = audit.select_public_package(
            "https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/synthetic.vpk", self.root)
        self.assertEqual(path, self.package)


if __name__ == "__main__":
    unittest.main()
