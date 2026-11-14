#!/usr/bin/env python3
"""Verify committed TOMLs against known-good data and structural invariants."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def norm(key: str, value):
    if key in ("method_index", "argc"):
        return int(value)
    if isinstance(value, str) and value.lower().startswith("0x"):
        return int(value, 16)
    return value


def check_ipc(problems: list[str]) -> None:
    for good in sorted((ROOT / "known_good" / "ipc").glob("*.toml")):
        got_path = ROOT / "ipc" / "steamclient" / f"{good.stem}.toml"
        if not got_path.exists():
            problems.append(f"missing {got_path.relative_to(ROOT)}")
            continue
        got = tomllib.loads(got_path.read_text())
        truth = tomllib.loads(good.read_text())
        for iface, entry in truth.items():
            if iface not in got:
                problems.append(f"{got_path.name}: missing interface {iface}")
                continue
            for key, value in entry.items():
                if isinstance(value, dict):
                    if key not in got[iface]:
                        problems.append(f"{got_path.name}: missing {iface}.{key}")
                        continue
                    for field in ("method_index", "funcHash", "wrapper_rva", "fencepost", "argc"):
                        if field not in value:
                            continue
                        if norm(field, got[iface][key].get(field)) != norm(field, value[field]):
                            problems.append(
                                f"{got_path.name}: {iface}.{key}.{field} "
                                f"{got[iface][key].get(field)} != {value[field]}")
                else:
                    if norm("vtable_rva", got[iface].get(key)) != norm("vtable_rva", value):
                        problems.append(
                            f"{got_path.name}: {iface}.{key} "
                            f"{got[iface].get(key)} != {value}")


def pattern_entries(path: Path) -> dict[str, int]:
    data = tomllib.loads(path.read_text())
    return {v["name"]: int(v["rva"], 16)
            for v in data.values()
            if isinstance(v, dict) and "name" in v and "rva" in v}


def check_patterns(problems: list[str]) -> None:
    for good in sorted((ROOT / "known_good" / "pattern" / "steamui").glob("*.json")):
        got_path = ROOT / "pattern" / "steamui" / f"{good.stem}.toml"
        if not got_path.exists():
            problems.append(f"missing {got_path.relative_to(ROOT)}")
            continue
        got = pattern_entries(got_path)
        truth = json.loads(good.read_text())
        for name, rva in truth.items():
            if got.get(name) != int(rva, 16):
                problems.append(
                    f"{got_path.name}: {name} 0x{got.get(name, 0):X} != {rva}")

    # Two different hooks must never resolve to the same function.
    for path in sorted((ROOT / "pattern" / "steamui").glob("*.toml")):
        got = pattern_entries(path)
        a = got.get("FillInAppOverview")
        b = got.get("BuildCompleteAppOverviewChange")
        if a is not None and b is not None and a == b:
            problems.append(
                f"{path.name}: FillInAppOverview and "
                f"BuildCompleteAppOverviewChange both 0x{a:X}")


def main() -> int:
    problems: list[str] = []
    check_ipc(problems)
    check_patterns(problems)
    if problems:
        for p in problems:
            print(f"FAIL {p}")
        return 1
    print("verify: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
