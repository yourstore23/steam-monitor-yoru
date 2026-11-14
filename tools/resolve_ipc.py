#!/usr/bin/env python3
"""Resolve IClientUser / IClientUtils IPC metadata from steamclient64.dll.

For each interface the vtable is located through its RTTI TypeDescriptor. Each
method's wrapper is identified by the method-name string it references, then the
first two 32-bit immediates the wrapper writes into its outgoing IPC buffer are
read as ``funcHash`` and ``fencepost``. Results are checked against the client's
dispatch switch (``CMP EAX, imm32``) and against a known-good TOML when one is
supplied.

Output schema matches IPCLoader.cpp:
    [Interface] interface_id, vtable_rva
    [Interface.Method] method_index, funcHash, wrapper_rva, fencepost, argc
"""

from __future__ import annotations

import argparse
import struct
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / "resolve_patterns.py")
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)

# Bound on how far into a wrapper we look for the name reference / constants.
# Wrappers are ~0x1B0 bytes; a wider window spills into the next sender and
# produces false name/hash matches.
WRAPPER_SCAN_BYTES = 0x200
# Consecutive non-function slots that end the vtable walk.
VTABLE_STOP_AFTER = 24
VTABLE_MAX_SLOTS = 600

# interface -> (interface_id, RTTI type descriptor, [(method, argc), ...])
IFACES = {
    "IClientUser": {
        "id": 1,
        "td": b".?AVIClientUserMap@@",
        "methods": [
            ("GetSteamID", 0),
            ("GetAppOwnershipTicketExtendedData", 2),
            ("RequestEncryptedAppTicket", 2),
            ("GetEncryptedAppTicket", 1),
        ],
    },
    "IClientUtils": {
        "id": 4,
        "td": b".?AVIClientUtilsMap@@",
        "methods": [
            ("GetAppID", 0),
            ("GetAPICallResult", 3),
        ],
    },
}


# --------------------------------------------------------------------------
# PE helpers (reuse the vendored parser)
# --------------------------------------------------------------------------

def image_base(buf: bytes) -> int:
    e = struct.unpack_from("<I", buf, 0x3C)[0]
    return struct.unpack_from("<Q", buf, e + 48)[0]


def data_spans(img) -> list[tuple[int, int]]:
    return [(va, max(vsz, rawsz)) for name, va, vsz, _raw, rawsz in img.secs
            if name in (b".rdata", b".data")]


def span_bytes(img, rva: int, size: int) -> bytes | None:
    out = bytearray()
    cur = rva
    while len(out) < size:
        o = img.rva2off(cur)
        if o is None:
            return None
        end = cur + 1
        while end < rva + size and img.rva2off(end) == o + (end - cur):
            end += 1
        out += bytes(img.buf[o:o + (end - cur)])
        cur = end
    return bytes(out)


def u32(img, rva: int) -> int | None:
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<I", img.buf, o)[0]


def u64(img, rva: int) -> int | None:
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<Q", img.buf, o)[0]


def cstring_at(img, rva: int) -> bytes | None:
    o = img.rva2off(rva)
    if o is None:
        return None
    end = img.buf.find(b"\x00", o)
    if end < 0 or end - o > 256:
        return None
    return bytes(img.buf[o:end])


# --------------------------------------------------------------------------
# RTTI -> vtable
# --------------------------------------------------------------------------

def find_td(img, spans, name: bytes) -> int | None:
    cands = set()
    key = bytes(name) + b"\x00"
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        off = 0
        while True:
            i = blob.find(key, off)
            if i < 0:
                break
            cands.add(rva + i - 16)
            off = i + 1
    if len(cands) != 1:
        return None
    return next(iter(cands))


def find_vtable(img, spans, td_rva: int, base: int) -> int | None:
    cols = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 4, 4):
            if struct.unpack_from("<I", blob, i)[0] != td_rva:
                continue
            col = rva + i - 12
            if u32(img, col) == 1:
                cols.add(col)
    if not cols:
        return None
    want = {base + c for c in cols}
    match = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 8, 8):
            if struct.unpack_from("<Q", blob, i)[0] in want:
                match.add(rva + i + 8)
    if len(match) != 1:
        return None
    return next(iter(match))


# --------------------------------------------------------------------------
# Wrapper inspection
# --------------------------------------------------------------------------

def wrapper_bytes(img, wrapper_rva: int, _pdata_sorted: list[int]) -> bytes | None:
    # pdata can contain several entries for one function (cold fragments), so the
    # next entry is NOT a function boundary. Scan a fixed window instead; the
    # name reference and both IPC constants sit within the first few hundred
    # bytes of the wrapper.
    o = img.rva2off(wrapper_rva)
    if o is None:
        return None
    return bytes(img.buf[o:o + WRAPPER_SCAN_BYTES])


def rip_lea_targets(code: bytes, code_rva: int):
    """Yield RVAs targeted by RIP-relative LEA (REX.W/REX.WR + 8D /r)."""
    i = 0
    n = len(code)
    while i + 6 < n:
        if code[i] in (0x48, 0x4C, 0x49, 0x4D) and code[i + 1] == 0x8D:
            modrm = code[i + 2]
            if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 -> RIP-relative
                disp = struct.unpack_from("<i", code, i + 3)[0]
                yield code_rva + i + 7 + disp
                i += 7
                continue
        i += 1


def wrapper_references(img, code: bytes, code_rva: int, name: bytes) -> bool:
    for target in rip_lea_targets(code, code_rva):
        if cstring_at(img, target) == name:
            return True
    return False


def imm32_stores(code: bytes) -> list[tuple[int, int]]:
    """Return (offset, value) for each `mov dword ptr [rsp/rbp+...], imm32`."""
    out = []
    i = 0
    n = len(code)
    while i + 6 < n:
        rex = 0
        if 0x40 <= code[i] <= 0x4F and i + 1 < n and code[i + 1] == 0xC7:
            rex = 1
        if code[i + rex] != 0xC7:
            i += 1
            continue
        m = code[i + rex + 1]
        mod = m >> 6
        rm = m & 7
        reg = (m >> 3) & 7
        if reg != 0:  # /0 only: MOV r/m32, imm32
            i += 1
            continue
        if mod == 1 and rm == 4 and code[i + rex + 2] == 0x24:
            # C7 44 24 disp8 imm32
            if i + rex + 8 <= n:
                out.append((i, struct.unpack_from("<I", code, i + rex + 4)[0]))
                i += rex + 8
                continue
        elif mod == 1 and rm == 5:
            # C7 45 disp8 imm32
            if i + rex + 7 <= n:
                out.append((i, struct.unpack_from("<I", code, i + rex + 3)[0]))
                i += rex + 7
                continue
        elif mod == 2 and rm == 4 and code[i + rex + 2] == 0x24:
            # C7 84 24 disp32 imm32
            if i + rex + 11 <= n:
                out.append((i, struct.unpack_from("<I", code, i + rex + 7)[0]))
                i += rex + 11
                continue
        i += 1
    return out


def extract_constants(code: bytes) -> tuple[int, int] | None:
    """First two large immediates written by the wrapper: funcHash, fencepost."""
    big = [v for _, v in imm32_stores(code) if v > 0xFFFF]
    if len(big) < 2:
        return None
    return big[0], big[1]


def dispatch_hashes(img) -> set[int]:
    """Every imm32 used by a `CMP EAX, imm32` (3D imm32) inside .text."""
    text = next(s for s in img.secs if s[0] == b".text")
    _, va, _vsz, raw, rawsz = text
    buf = img.buf[raw:raw + rawsz]
    out = set()
    i = 0
    n = len(buf)
    while True:
        i = buf.find(b"\x3d", i)
        if i < 0 or i + 5 > n:
            break
        out.add(struct.unpack_from("<I", buf, i + 1)[0])
        i += 5
    return out


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------

def vtable_slots(img, vt: int, base: int, pdata: set[int]) -> list[tuple[int, int]]:
    """(slot_index, wrapper_rva) for slots that point at a real function."""
    slots = []
    misses = 0
    for idx in range(VTABLE_MAX_SLOTS):
        raw = u64(img, vt + idx * 8)
        if raw is None:
            break
        rva = raw - base if raw >= base else None
        if rva is None or rva not in pdata:
            misses += 1
            if misses >= VTABLE_STOP_AFTER:
                break
            continue
        misses = 0
        slots.append((idx, rva))
    return slots


def resolve_iface(img, spans, base, pdata, pdata_sorted, iface, spec, cmp_hashes):
    td = find_td(img, spans, spec["td"])
    if td is None:
        return None, f"no TypeDescriptor {spec['td']!r}"
    vt = find_vtable(img, spans, td, base)
    if vt is None:
        return None, "vtable not unique"
    slots = vtable_slots(img, vt, base, pdata)
    if not slots:
        return None, "empty vtable"

    resolved = {}
    used_wrappers = {}
    used_hashes = {}

    for name, argc in spec["methods"]:
        name_bytes = name.encode()
        match = None
        for idx, wrapper_rva in slots:
            code = wrapper_bytes(img, wrapper_rva, pdata_sorted)
            if code is None:
                continue
            if not wrapper_references(img, code, wrapper_rva, name_bytes):
                continue
            consts = extract_constants(code)
            if consts is None:
                continue
            func_hash, fence = consts
            if func_hash not in cmp_hashes:
                continue
            match = (idx, wrapper_rva, func_hash, fence)
            break
        if match is None:
            return None, f"{name}: no vtable slot references its name with a valid hash"
        idx, wrapper_rva, func_hash, fence = match
        if wrapper_rva in used_wrappers:
            return None, (f"{name}: wrapper 0x{wrapper_rva:X} already used by "
                          f"{used_wrappers[wrapper_rva]}")
        if func_hash in used_hashes:
            return None, (f"{name}: funcHash 0x{func_hash:08X} already used by "
                          f"{used_hashes[func_hash]}")
        used_wrappers[wrapper_rva] = name
        used_hashes[func_hash] = name
        resolved[name] = (idx, wrapper_rva, func_hash, fence, argc)

    return {"vtable": vt, "methods": resolved}, None


def render_toml(resolved) -> str:
    parts = []
    for iface, spec, data in resolved:
        parts.append("\n".join(
            [f"[{iface}]", f'interface_id = {spec["id"]}',
             f'vtable_rva = "0x{data["vtable"]:X}"']))
        for name, _argc in spec["methods"]:
            idx, wrapper_rva, func_hash, fence, argc = data["methods"][name]
            parts.append("\n".join(
                [f"[{iface}.{name}]", f"method_index = {idx}",
                 f'funcHash = "0x{func_hash:08X}"',
                 f'wrapper_rva = "0x{wrapper_rva:X}"',
                 f'fencepost = "0x{fence:08X}"', f"argc = {argc}"]))
    head = "# MACHINE-GENERATED by tools/resolve_ipc.py - do not hand-edit"
    return head + "\n" + "\n\n".join(parts) + "\n"


def _norm(key: str, value):
    if key in ("method_index", "argc"):
        return int(value)
    if isinstance(value, str) and value.lower().startswith("0x"):
        return int(value, 16)
    return value


def known_good_mismatches(text: str, truth: dict) -> list[str]:
    try:
        got = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [f"generated TOML is not valid: {exc}"]
    problems = []
    for iface, spec in IFACES.items():
        t = truth.get(iface)
        if t is None:
            continue
        if _norm("vtable_rva", t.get("vtable_rva")) != _norm("vtable_rva", got[iface]["vtable_rva"]):
            problems.append(f"{iface}.vtable_rva: {got[iface]['vtable_rva']} != {t['vtable_rva']}")
        for name, _argc in spec["methods"]:
            if name not in t:
                continue
            g = got[iface][name]
            e = t[name]
            for key in ("method_index", "funcHash", "wrapper_rva", "fencepost", "argc"):
                if _norm(key, g.get(key)) != _norm(key, e.get(key)):
                    problems.append(f"{iface}.{name}.{key}: {g.get(key)} != {e.get(key)}")
    return problems


def cmd_resolve(args) -> int:
    dll = Path(args.dll)
    img = rp.mp.Image(dll)
    spans = data_spans(img)
    if not spans:
        print("FAIL: no data sections")
        return 1
    base = image_base(img.buf)
    pdata_sorted = sorted(img.pdata_entries())
    pdata = set(pdata_sorted)
    cmp_hashes = dispatch_hashes(img)
    print(f"image base=0x{base:X} pdata={len(pdata)} cmp_imm32={len(cmp_hashes)}")

    resolved, failed = [], []
    for iface, spec in IFACES.items():
        data, err = resolve_iface(img, spans, base, pdata, pdata_sorted,
                                  iface, spec, cmp_hashes)
        if err is not None:
            failed.append((iface, err))
            print(f"FAIL {iface}: {err}")
            continue
        resolved.append((iface, spec, data))
        print(f"{iface}: vtable=0x{data['vtable']:X} " +
              " ".join(f"{m}@slot{data['methods'][m][0]}=0x{data['methods'][m][2]:08X}"
                       for m, _ in spec["methods"]))

    if failed:
        return 1

    text = render_toml(resolved)

    if args.verify:
        truth = tomllib.load(open(args.verify, "rb"))
        problems = known_good_mismatches(text, truth)
        if problems:
            for p in problems:
                print(f"MISMATCH {p}")
            return 1
        print(f"verify: matches {args.verify}")

    if args.out_dir:
        sha = __import__("hashlib").sha256(dll.read_bytes()).hexdigest()
        out = Path(args.out_dir) / "steamclient" / f"{sha}.toml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, newline="\n")
        print(f"wrote {out}")

    if args.print:
        print(text)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--dll", required=True)
    r.add_argument("--out-dir", default=None)
    r.add_argument("--verify", default=None)
    r.add_argument("--print", action="store_true")
    args = ap.parse_args()
    if args.cmd == "resolve":
        return cmd_resolve(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
