# steam-monitor-yoru

Per-SHA hook metadata for OpenSteamTool, generated from Valve's public Steam
client update CDN.

Every 15 minutes CI polls the stable and beta win64 manifests. When a new build
appears it downloads `steamclient64.dll` and `SteamUI.dll`, resolves the hook
patterns and IPC metadata from the binaries, verifies the result, and commits
per-SHA TOMLs. Client binaries are never committed (`bins/` is ignored).

## Layout

```
pattern/steamclient/<sha>.toml   hook RVAs + byte signatures
pattern/steamui/<sha>.toml       same, for steamui.dll
ipc/steamclient/<sha>.toml       interface/method/funcHash/fencepost
pattern/versions.json            client version -> SHA pair
known_good/                      reference values for current builds
tools/                           fetch + resolvers + verifier
```

## Local run

```sh
python3 -m unittest discover -s tests -v

python3 tools/fetch_client.py --out bins/ --channels stable beta \
  --versions-file pattern/versions.json
python3 tools/resolve_patterns.py resolve \
  --dll bins/stable/steamclient64.dll --side steamclient --out-dir pattern/
python3 tools/resolve_patterns.py resolve \
  --dll bins/stable/SteamUI.dll --side steamui --out-dir pattern/
python3 tools/resolve_ipc.py resolve \
  --dll bins/stable/steamclient64.dll --out-dir ipc/
python3 tools/verify_repo.py
```

## OpenSteamTool config

Point `[remote]` at this repo:

```toml
[remote]
url_templates = [
  "https://cdn.jsdelivr.net/gh/yourstore23/steam-monitor-yoru@main/{channel}/{component}/{sha256}.toml",
  "https://raw.githubusercontent.com/yourstore23/steam-monitor-yoru/main/{channel}/{component}/{sha256}.toml",
]
```

`{channel}` is `pattern` or `ipc`, `{component}` is `steamclient` or `steamui`,
and `{sha256}` is the SHA-256 of the corresponding Valve DLL.

## Notes

- No Steam login, API key, or VPS is required; GitHub Actions does the work.
- Scheduled runs are best-effort. A new build can take up to ~15 minutes (plus
  GitHub scheduling delay) to appear.
- If resolution fails, the run publishes nothing and opens an issue with the
  log.
- `known_good/` stores one reference per build that has been verified by hand.
  New builds are still derived automatically.
