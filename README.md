# macir.sh — macOS IR Evidence Collector

Forensically-sound, declaratively-configurable incident-response evidence
collector for **network-isolated macOS hosts** (Ventura+ / Sonoma / Sequoia),
tuned for the **Odyssey / Poseidon / AMOS** infostealer family delivered via
ClickFix (the "paste this into Terminal" lure).

It collects volatile state, on-disk artifacts, persistence, unified logs,
FSEvents, TCC, and a **credential blast-radius** map — then hashes everything,
writes a SHA-256 manifest, and bundles a `<CASE_ID>.tar.gz`.

> **Atime is evidence.** When a local APFS snapshot can be taken, all on-disk
> reads are routed through a **read-only snapshot mount**, so the collector
> never clobbers the access-time signal Phase 5 depends on.

---

## Requirements

| Requirement | Notes |
|---|---|
| macOS Ventura (13) or later | Uses `sfltool dumpbtm`, `systemextensionsctl`, BTM. |
| `zsh` ≥ 5.8 (system default) | `zparseopts -F`, `zsh/datetime`, `zsh/zutil`. |
| **root** | `sudo -E` (the `-E` preserves your env-var overrides). |
| External write media | Output **must not** be on the boot volume (refused). |
| ~10 GB free (default) | Unified log archive + raw tracev3 can be large. |

No third-party tools. All binaries are referenced by **absolute path**
(`/usr/bin/...`) by design — see [Security model](#security-model).

---

## Install

```sh
# Copy to your external evidence volume (recommended) or any path.
install -m 0755 macir.sh /Volumes/IR/macir.sh
```

No build step. Optionally place an `macir.conf` next to your evidence base
(see [Configuration](#configuration)).

---

## Quick start

```sh
# Full collection to /Volumes/IR, auto case-id, snapshot-backed reads
sudo -E /Volumes/IR/macir.sh

# Preview the resolved plan — NO side effects, no mounts, no writes
sudo -E /Volumes/IR/macir.sh --dry-run

# Fast triage: freeze, volatile, logs, finalize only; skip live sampler
sudo -E /Volumes/IR/macir.sh -p "0 1 4 8" --no-powermetrics

# Forensic-pure: never mutate the host (no snapshot, no powermetrics)
#   (note: --no-snapshot means atimes WILL change as files are read)
sudo -E /Volumes/IR/macir.sh --no-powermetrics --no-snapshot

# Custom case with a campaign IOC file and bigger sample cap
sudo -E /Volumes/IR/macir.sh \
  -i CASE-2026-ACME-01 \
  -I /Volumes/IR/CASE-2026-ACME-01/iocs.txt \
  --max-sample $((200*1024*1024)) -w 14
```

---

## Usage

```text
sudo -E macir.sh [options]
```

### Paths / identity
| Flag | Arg | Default | Meaning |
|---|---|---|---|
| `-o`, `--evidence-base` | DIR | `/Volumes/IR` | Output root (must be external media). |
| `-i`, `--case-id` | ID | `IR-<ts>-<host>` | Case identifier; names the bundle. |
| `-u`, `--target-user` | USER | `$SUDO_USER` | User whose home/artifacts are triaged. |
| `-c`, `--config` | FILE | `<base>/macir.conf` | Config file to source. |
| `-I`, `--ioc-file` | FILE | — | Extra IOCs, one per line (`#` comments ok). |

### Windows / sizing
| Flag | Arg | Default | Meaning |
|---|---|---|---|
| `-l`, `--lookback` | DUR | `14d` | Unified-log lookback (`log show --last`). |
| `-w`, `--window` | DAYS | `30` | mtime/btime change-bracket. |
| `--pam-window` | DAYS | `90` | PAM modification lookback. |
| `--max-sample` | BYTES | `52428800` | Auto-capture size cap (50 MiB). |
| `--min-free` | GB | `10` | Free-space warning threshold. |

### Selection / behavior
| Flag | Default | Meaning |
|---|---|---|
| `-p`, `--phases "LIST"` | `0 1 2 3 4 5 6 7 8` | Phases to run (space-separated). |
| `--no-snapshot` | off | Skip APFS snapshot/mount (**atime will change**). |
| `--no-diagnostics` | off | Skip large `/var/db/diagnostics` tarball. |
| `--no-powermetrics` | off | Skip live `powermetrics` sampler. |
| `--no-full-disk` | off | Skip whole-volume time-bracket `find`. |
| `--no-lsof-all` | off | Skip full `lsof -nP`. |
| `--no-bundle` | off | Leave output uncompressed (no `tar.gz`). |
| `--color WHEN` | `auto` | `auto` \| `always` \| `never` (honors `NO_COLOR`). |

### General
| Flag | Meaning |
|---|---|
| `-n`, `--dry-run` | Resolve config, print plan, exit. No collection. |
| `-V`, `--version` | Print version and exit. |
| `-h`, `--help` | Show help and exit. |

Unknown flags are rejected (`zparseopts -F`) with a clear error and exit code 2.

---

## Configuration

### Precedence (lowest → highest)
```
built-in defaults  <  macir.conf  <  environment  <  CLI flags
```

* The config file is located via `-c`, else `$IR_CONFIG`, else
  `<evidence-base>/macir.conf`. It is **sourced as zsh**, so it can set any
  scalar, toggle, array (`KNOWN_BAD_PATHS`, `PRUNE_DIRS`, `IOC_STRINGS`) or map
  (`EXT_WALLETS`).
* Because of `sudo`, pass env overrides with `sudo -E` (e.g.
  `sudo -E CHANGE_WINDOW_DAYS=7 ./macir.sh`).
* The **effective** config (source, phases, windows, toggles, IOC count) is
  printed by `--dry-run` and logged to `_meta/run.log` for chain of custody.

See `macir.conf.example` for every knob.

---

## Output layout

```
<evidence-base>/<CASE_ID>/
├── README.md                  # auto-generated bundle summary + verify cmd
├── _meta/
│   ├── run.log                # full command log (chain of custody)
│   ├── run.err                # stderr / non-zero exits
│   └── MANIFEST.sha256        # SHA-256 of every collected file
├── 00_freeze/                 # clock, uptime, snapshot reference
├── 01_volatile/               # ps, lsof, netstat, pf, kexts, sysexts
├── 02_disk/                   # known-bad paths, time-bracket, Mach-O, samples
├── 03_persistence/            # LaunchAgents/Daemons, BTM, cron, shell init, sudoers
├── 04_logs/                   # unified log archive + tracev3, TCC, FSEvents, history
├── 05_secrets/                # Keychain NAMES + browser/wallet/dev-secret atimes
├── 06_samples/                # additional suspect Mach-O sweep
├── 07_sysmeta/                # OS version, XProtect/Gatekeeper, FileVault, MDM
└── 08_final/
    ├── ioc_hits.txt           # fixed-string IOC sweep across all output
    └── COMPROMISE_DEPTH.md     # analyst assessment template
```

Bundle: `<evidence-base>/<CASE_ID>.tar.gz` (+ `.sha256`) unless `--no-bundle`.

---

## Triage order (start here)

1. `08_final/ioc_hits.txt` — campaign IOCs found in collected data.
2. `04_logs/log_helper.txt` + `log_curl.txt` — Stage-3 exec + C2 contact.
3. `04_logs/log_osascript_dialog.txt` — fake password dialog displayed.
4. `04_logs/paste_evidence.txt` — the exact pasted command line.
5. `03_persistence/apple_impersonators.txt` — impersonating LaunchAgents.
6. `05_secrets/browser_credstores.txt` + `wallets.txt` — **atime** access proof.
7. Fill in `08_final/COMPROMISE_DEPTH.md`.

---

## Security model

* **Absolute tool paths are intentional and NOT configurable.** On a
  potentially compromised host, allowing tool paths to be overridden would
  reintroduce PATH-hijack / trojaned-binary risk. This is a deliberate hardening
  choice, not an oversight.
* **`sudo -E` contract** is fixed for the same reason; only data/behavior knobs
  are configurable.
* **Phase 5 reads no secret contents** — only names (Keychain) and file
  metadata (atime/mtime/size/xattr/hash). No keys, passwords, or seeds are
  written to disk.
* **Host mutation:** `tmutil localsnapshot`, `powermetrics`, and `mdfind` touch
  the live system. Disable with `--no-snapshot` / `--no-powermetrics` when
  forensic purity outweighs the corresponding evidence. The chosen read source
  (snapshot vs live) is recorded in the bundle README.

---

## Verifying integrity

```sh
cd <evidence-base>/<CASE_ID>
shasum -a 256 -c _meta/MANIFEST.sha256

# Bundle hash
shasum -a 256 -c <evidence-base>/<CASE_ID>.tar.gz.sha256
```

Open the unified log archive on an analyst Mac:

```sh
log show --archive <CASE_ID>/04_logs/unifiedlog.logarchive --info \
  --predicate 'process == "curl" OR process == "osascript"'
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or `--help`/`--version`/`--dry-run`). |
| `1` | Preflight failure (not root, no media, boot-volume target, etc.). |
| `2` | Invalid/unknown option or non-numeric config value. |

Individual collection steps never abort the run; failures are logged to
`_meta/run.err` and surfaced as `WARN` lines.

---

## License / handling

Evidence bundles may contain **highly sensitive** data (history, tokens, file
paths revealing secrets). Treat per your IR data-handling policy; transfer over
trusted media only.
