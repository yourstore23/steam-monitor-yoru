import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import resolve_patterns as R  # noqa: E402


class FakeCtx:
    def __init__(self, entries, sizes, e8):
        self.entries = sorted(entries)
        self._sizes = sizes
        self._e8 = e8

    def refs_by_func(self):
        return {}

    def func_size(self, f):
        return self._sizes.get(f, 0)

    def func_of(self, rva):
        prev = None
        for e in self.entries:
            if e <= rva:
                prev = e
            else:
                break
        return prev

    def e8_count_many(self, targets):
        return {t: self._e8.get(t, 0) for t in targets}


class PipeClientTests(unittest.TestCase):
    def test_body_after_a_0xa0_header(self):
        # Stable layout: 0x150 chunk, GetPipeClient at +0xA0.
        ctx = FakeCtx([0x1000, 0x1150], {0x1000: 0x150}, {0x10A0: 15})
        self.assertEqual(R.p2_pipeclient(ctx, 0xF00), (0x10A0, None))

    def test_body_after_a_0xb0_header(self):
        # Beta 1795048523 layout: 0x160 chunk, GetPipeClient at +0xB0.
        ctx = FakeCtx([0x2000, 0x2160], {0x2000: 0x160}, {0x20B0: 16})
        self.assertEqual(R.p2_pipeclient(ctx, 0x1E00), (0x20B0, None))


if __name__ == "__main__":
    unittest.main()
