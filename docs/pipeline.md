# steam-monitor-yoru pipeline

Every 15 minutes CI polls the stable and beta win64 manifests. On a new build it
downloads the DLLs, re-resolves all hook signatures and IPC metadata from
scratch, verifies the result, and publishes per-SHA TOMLs.

1. `tools/fetch_client.py` -> `bins/<channel>/` (exit 2 = already published,
   exit 3 = only version records changed)
2. `tools/resolve_patterns.py` -> `pattern/<side>/<sha256>.toml`
3. `tools/resolve_ipc.py` -> `ipc/steamclient/<sha256>.toml`
4. `tools/verify_repo.py` + `tests/` must pass
5. On success: `README.md` is re-rendered with knap and committed with
   `pattern/` + `ipc/`
6. Any failure -> nothing is published and an issue is opened

## Layout

```
pattern/steamclient/<sha>.toml   hook RVAs + byte signatures
pattern/steamui/<sha>.toml       same, for SteamUI.dll
ipc/steamclient/<sha>.toml       interface/method/funcHash/fencepost
pattern/versions.json            client version -> SHA pair (README source)
known_good/                      verified reference values for specific SHAs
templates/readme.md              knap template for README.md
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

## Known-good data

`known_good/` stores reference values for builds that have been checked by hand:
the IPC table (`known_good/ipc/<sha>.toml`) and critical pattern RVAs
(`known_good/pattern/steamui/<sha>.json`). It is a CI safety net, not an input
to the resolvers and not used at runtime:

- A new build without a known-good entry is resolved and published normally.
- If a build has an entry, `tools/verify_repo.py` and `tests/` fail when the
  derived values differ, so a resolver regression cannot silently publish wrong
  data.
- Adding a reference is optional and only needs the SHA and the verified values.

## OpenSteamTool config

```toml
[remote]
url_templates = [
  "https://cdn.jsdelivr.net/gh/yourstore23/steam-monitor-yoru@main/{channel}/{component}/{sha256}.toml",
  "https://raw.githubusercontent.com/yourstore23/steam-monitor-yoru/main/{channel}/{component}/{sha256}.toml",
]
```

`{channel}` is `pattern` or `ipc`, `{component}` is `steamclient` or `steamui`,
and `{sha256}` is the SHA-256 of the corresponding Valve DLL.
