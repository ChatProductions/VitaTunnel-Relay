#!/usr/bin/env python3
"""Regression tests for archived, public, text-only Vita diagnostics."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_nfsmw_trace_evidence import (  # noqa: E402
    DEFAULT_DIAGNOSTICS, EvidenceError, evaluate, parse_trace,
)


class ArchivedEvidenceTests(unittest.TestCase):
    def test_real_archived_fault_snapshots(self):
        result = evaluate()
        self.assertEqual([result["stages"][s]["fileio_calls"] for s in ("r10", "r11", "r15")],
                         [0, 1, 2])
        self.assertEqual(result["stages"]["r10"]["fault_pc"],
                         result["stages"]["r15"]["fault_pc"])
        self.assertFalse(result["gameplay_verified"])
        self.assertFalse(result["disc_service_verified"])
        self.assertFalse(result["fileio_1048_open_abi_verified"])
        self.assertFalse(result["new_hardware_execution_claimed"])

    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fault.bin"
            path.write_text("pc=004958E4\npc=004958E4\n", encoding="utf-8")
            with self.assertRaises(EvidenceError):
                parse_trace(path)

    def test_missing_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(EvidenceError):
                evaluate(Path(td))

    def test_mutated_fault_counters_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td)
            for filename in ("00000065-startup.bin", "00000066-fault.bin",
                             "00000067-progress.bin", "00000071-startup.bin",
                             "00000072-fault.bin", "00000073-progress.bin",
                             "00000103-startup.bin", "00000104-fault.bin",
                             "00000105-progress.bin"):
                shutil.copyfile(DEFAULT_DIAGNOSTICS / filename, destination / filename)
            fault = destination / "00000104-fault.bin"
            content = fault.read_text(encoding="utf-8")
            self.assertIn("rpc_send_size=1048", content)
            fault.write_text(content.replace("rpc_send_size=1048",
                                             "rpc_send_size=272"), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                evaluate(destination)


if __name__ == "__main__":
    unittest.main()
