#!/usr/bin/env python3
"""Fail-closed, asset-free regression checks for archived public NFSMW Vita traces.

These .bin files are UTF-8 key=value diagnostics, NOT game/firmware binaries.
Only compare like-for-like fault snapshots; 6M-cycle progress snapshots are
earlier checkpoints, not the final execution state.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_DIAGNOSTICS = Path(__file__).resolve().parents[1] / "diagnostics" / "NFMRA0001"
TRACE_IDS = {"r10": (65, 66, 67), "r11": (71, 72, 73), "r15": (103, 104, 105)}
EXPECTED = {
    "r10": {
        "build": "nfsmw-aot-20261029-trace-r10",
        "reason": "syscall", "pc": "004958E4", "cycles": "6871312",
        "aot_function_instructions": "3805493", "native_iop_packets": "11",
        "fileio_binds": "1", "fileio_calls": "0",
        # r10's unknown_cid 0xE was a semaphore, not a client pointer.
        "native_iop_unknown_cid": "0000000E",
    },
    "r11": {
        "build": "nfsmw-aot-20261029-reply-r11",
        "reason": "syscall", "pc": "004958E4", "cycles": "6871312",
        "aot_function_instructions": "3805493", "native_iop_packets": "11",
        "fileio_binds": "1", "fileio_calls": "1",
        "fileio_last_fno": "255",
    },
    "r15": {
        "build": "nfsmw-aot-native-fileio8-r15",
        "reason": "syscall", "pc": "004958E4", "cycles": "6872043",
        "aot_function_instructions": "3805635", "native_iop_packets": "12",
        "fileio_binds": "1", "fileio_calls": "2",
        "fileio_last_fno": "0", "rpc_fno": "0",
        "rpc_send_size": "1048", "rpc_recv_size": "4",
        "rpc_client": "005D0DC0", "rpc_bound_fileio": "005D0DC0",
        "rpc_server": "001E3000", "rpc_mode": "1", "rpc_sema": "15",
        "rpc_fileio_candidate": "1", "rpc_reject_flags": "128",
        "a0_words": "005CF6C0,001E4000,00000418,00000000,205CDE40,001F0000",
    },
}


class EvidenceError(ValueError):
    """Missing, modified, or internally inconsistent public trace."""


def parse_trace(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise EvidenceError(f"missing trace: {path}")
    fields: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "=" not in line:  # Startup includes the free-text AOT-armed marker.
            continue
        key, value = line.split("=", 1)
        if not key or key in fields:
            raise EvidenceError(f"{path.name}:{lineno}: invalid or duplicate key {key!r}")
        fields[key] = value
    return fields


def require(fields: dict[str, str], key: str, expected: str, stage: str) -> None:
    actual = fields.get(key)
    if actual != expected:
        raise EvidenceError(f"{stage}: {key} expected {expected!r}, got {actual!r}")


def evaluate(directory: Path = DEFAULT_DIAGNOSTICS) -> dict:
    stages: dict[str, dict] = {}
    for name, (startup_id, fault_id, progress_id) in TRACE_IDS.items():
        startup = parse_trace(directory / f"{startup_id:08d}-startup.bin")
        fault = parse_trace(directory / f"{fault_id:08d}-fault.bin")
        progress = parse_trace(directory / f"{progress_id:08d}-progress.bin")
        for key, value in EXPECTED[name].items():
            require(fault, key, value, name)
        require(startup, "build", fault["build"], name + " startup")
        require(progress, "cycles", "6000000", name + " progress")
        require(progress, "pc", "0015E114", name + " progress")
        require(fault, "ioprp_valid", "1", name)
        require(fault, "ioprp_size", "269889", name)
        if int(progress["cycles"]) >= int(fault["cycles"]):
            raise EvidenceError(f"{name}: progress checkpoint is not earlier than fault")
        stages[name] = {
            "build": fault["build"],
            "fault_pc": fault["pc"],
            "fault_cycles": int(fault["cycles"]),
            "aot_instructions": int(fault["aot_function_instructions"]),
            "fileio_calls": int(fault["fileio_calls"]),
            "last_fileio_function": int(fault.get("fileio_last_fno", "4294967295")),
        }
    # Correlate the r15 EE->IOP SIF1 DMA descriptor with its RPC envelope.
    r15 = parse_trace(directory / "00000104-fault.bin")
    dma = [int(word, 16) for word in r15["a0_words"].split(",")]
    if len(dma) != 6 or dma[:3] != [0x005CF6C0, 0x001E4000, 0x418]:
        raise EvidenceError("r15: SIF1 DMA descriptor changed")
    if dma[2] != int(r15["rpc_send_size"]):
        raise EvidenceError("r15: SIF1 DMA size does not match RPC send size")
    if stages["r10"]["fault_pc"] != stages["r11"]["fault_pc"] or (
        stages["r11"]["fault_pc"] != stages["r15"]["fault_pc"]
    ):
        raise EvidenceError("fault PCs differ; re-evaluate startup conclusions")
    return {
        "evidence": "archived public diagnostics only",
        "stages": stages,
        "observations": {
            "r10_to_r11": "FILEIO call count 0 -> 1; same fault PC and AOT count",
            "r11_to_r15": "FILEIO call count 1 -> 2; second call is unverified 1048-byte OPEN",
            "r15_dma_source": "005CF6C0",
            "r15_dma_destination": "001E4000",
            "r15_dma_size": dma[2],
            "r15_ee_sdk_tag_is_not_verified_iop_version": True,
        },
        "gameplay_verified": False,
        "disc_service_verified": False,
        "fileio_1048_open_abi_verified": False,
        "new_hardware_execution_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostics", type=Path, default=DEFAULT_DIAGNOSTICS)
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(args.diagnostics), indent=2, sort_keys=True))
    except (EvidenceError, UnicodeError) as exc:
        parser.exit(1, f"evidence check FAILED: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
