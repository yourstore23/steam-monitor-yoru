import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import resolve_ipc as R  # noqa: E402

SHA = "669fa08e259277fbf5a1dfe15ce88afe734e89151194304b44d92f418dcc985b"


class IpcResolverTests(unittest.TestCase):
    def test_committed_ipc_matches_known_good(self):
        got = tomllib.loads((ROOT / "ipc" / "steamclient" / f"{SHA}.toml").read_text())
        truth = tomllib.loads((ROOT / "known_good" / "ipc" / f"{SHA}.toml").read_text())
        for iface, entry in truth.items():
            for key, value in entry.items():
                if isinstance(value, dict):
                    for field in ("method_index", "funcHash", "wrapper_rva", "fencepost", "argc"):
                        self.assertEqual(
                            R._norm(field, got[iface][key][field]),
                            R._norm(field, value[field]),
                            f"{iface}.{key}.{field}")
                else:
                    self.assertEqual(
                        R._norm("vtable_rva", got[iface][key]),
                        R._norm("vtable_rva", value),
                        f"{iface}.{key}")

    def test_extract_constants_skips_small_values(self):
        # MOV [rsp+30], 2 (argc) followed by the funcHash and fencepost stores.
        code = bytes.fromhex("c744243002000000c74424301cbbd625c744243063f54626")
        self.assertEqual(R.extract_constants(code), (0x25D6BB1C, 0x2646F563))

    def test_extract_constants_requires_two_large_values(self):
        self.assertIsNone(R.extract_constants(bytes.fromhex("c744243002000000")))

    def test_mismatch_is_detected(self):
        truth = tomllib.loads((ROOT / "known_good" / "ipc" / f"{SHA}.toml").read_text())
        text = (ROOT / "ipc" / "steamclient" / f"{SHA}.toml").read_text()
        bad = text.replace('funcHash = "0x25D6BB1C"', 'funcHash = "0xBBB80477"')
        problems = R.known_good_mismatches(bad, truth)
        self.assertTrue(any("RequestEncryptedAppTicket" in p for p in problems))

    def test_wrapper_hash_is_unique(self):
        truth = tomllib.loads((ROOT / "known_good" / "ipc" / f"{SHA}.toml").read_text())
        req = truth["IClientUser"]["RequestEncryptedAppTicket"]
        get = truth["IClientUser"]["GetEncryptedAppTicket"]
        self.assertNotEqual(req["funcHash"], get["funcHash"])
        self.assertNotEqual(req["wrapper_rva"], get["wrapper_rva"])


class PatternFeedTests(unittest.TestCase):
    def test_fill_and_buildcomplete_are_distinct(self):
        path = ROOT / "pattern" / "steamui" / "2dfb0a5d50dd90667549cc7d413c7bfb0794c9af4ebaf08bf1cf7d938a11ea93.toml"
        data = tomllib.loads(path.read_text())
        entries = {v["name"]: int(v["rva"], 16) for v in data.values()
                   if isinstance(v, dict) and "name" in v}
        self.assertEqual(entries["FillInAppOverview"], 0x63B0D0)
        self.assertEqual(entries["BuildCompleteAppOverviewChange"], 0x634280)
        self.assertNotEqual(entries["FillInAppOverview"],
                            entries["BuildCompleteAppOverviewChange"])


if __name__ == "__main__":
    unittest.main()
