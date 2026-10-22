# argus

Read-only host compromise and malware triage scanner for macOS and Linux.

argus is an antivirus-style host sweep built for the October 2026 software supply-chain
and credential-theft wave, plus general host-compromise, persistence, crypto-miner, and
patch-posture checks. A deterministic Bash engine does the detection; an operator (or an
AI agent via the bundled skill) triages the output. It ships as a Claude Code skill and
also runs standalone from the shell.

It is designed to be safe to run on a developer or security engineer's own machine: it
never changes anything, never executes a suspect artifact, and never phones home.

## What it detects

- The October 2026 supply-chain IOCs: LiteLLM 1.107.0 (PyPI and Docker), Tensorlake npm
  0.5.144 (Shai-Hulud/ChainDrop worm), SubQuery @subql/common 5.8.3, the OVHcloud CLI
  backdoor (GlassWorm), and the Rank Math PRO 3.0.123 trojan. See `iocs.tsv`.
- Persistence: launchd agents and daemons, systemd units, cron, rc files, pipe-to-shell
  droppers in shell rc files, authorized_keys changes, UID 0 accounts, third-party kexts
  and system extensions, `/etc/ld.so.preload`.
- Runtime: crypto-miner process names, executables running from temp dirs, sustained high
  CPU, listening sockets, outbound connections to mining-pool ports or known IOC addresses,
  and Linux unlinked (deleted) executables. Signals are correlation-weighted so a single
  weak match does not raise an alarm.
- Package hygiene: unusual Python `.pth` startup hooks and an editor-extension inventory.
- Security posture: SIP and Gatekeeper state (macOS), presence of the compromised eMudhra
  (emSign) CA, optional ClamAV, and optional Trivy for CRITICAL known-CVE findings.
- Patch posture: Node, Go, Tailscale, and PHP versions against the October 2026 fixes, and
  any local WordPress UpdraftPlus, Rank Math, or Bricksforge trees. See `PATCHES.md`.

## Safety contract

argus is strictly read-only and enforces this in code:

- Never deletes, kills, quarantines, chmods, or installs anything.
- Never executes a possibly-compromised artifact. Suspect package versions are read from
  the filesystem, never by running `pip`, `npm`, or the vendor CLI. Any Python it runs
  uses `-I -S`, so `.pth` and `sitecustomize` payloads cannot load.
- Never phones home. All IOC matching is local. The only network actions are opt-in and
  explicit: `--trivy` fetches Trivy's vulnerability database, and `--clamav` uses a local
  engine.
- Redacts matched content. It reports `file:line` and which IOC matched, not the matching
  line, so it does not spill secrets from shell history or `.env` files into the report.
- Remediation is never automatic. argus recommends; a human approves and acts.

## Requirements

- bash (works with macOS's bundled bash 3.2), standard POSIX tools.
- Optional: `lsof` (present on macOS; falls back to `ss` on Linux), `clamscan`, `trivy`.
- No root required. Checks that need elevated access are recorded as skipped, not failed.

## Install

As a Claude Code skill (recommended):

```
git clone git@github.com:devx-commerce/argus.git ~/.claude/skills/argus
```

Once installed, run it in Claude Code with the `/argus` slash command, which executes the
skill directly. It also auto-triggers on requests like "scan my laptop", "am I compromised",
"check for crypto mining", or "run argus".

Standalone:

```
git clone git@github.com:devx-commerce/argus.git
cd argus && chmod +x scan.sh install-trivy.sh
./scan.sh
```

## Usage

```
scan.sh                 default: read-only, fully local, macOS or Linux
scan.sh --trivy         also run pinned Trivy (CRITICAL only); requires install-trivy.sh first
scan.sh --clamav        also run ClamAV, only if it is already installed
scan.sh --root DIR      scan only DIR (filesystem layers); used for positive-control tests
scan.sh --out DIR       write the report to DIR (default: a fresh temp dir, printed at the end)
scan.sh --quiet         print only the summary; the full report is still written
scan.sh --no-color      disable ANSI color
scan.sh --help          usage
```

The scanner prints a summary and writes `findings.tsv` and `report.txt` to the out dir.

Exit codes: 0 clean or info-only, 1 if any HIGH finding, 2 if any CRIT finding. This makes
it usable as a gate in CI or a cron job.

## Trivy (optional CRITICAL layer)

Trivy adds known-CVE, secret, and misconfiguration detection across OS packages and
language dependencies. Because the whole threat theme this month is poisoned release
pipelines, Trivy is pinned and checksum-verified, and argus never auto-installs it.

```
./install-trivy.sh        # installs the pinned version, verifies sha256, into ~/.local/bin
./scan.sh --trivy         # CRITICAL findings only
```

Override the pin with `ARGUS_TRIVY_PIN=x.y.z` and the install dir with `ARGUS_BIN=/path`.

## Deep mode (multi-agent verification)

For ambiguous or numerous HIGH/CRIT findings, `deep-mode.workflow.js` fans out one
read-only investigator agent per finding, each gathering context on the flagged file,
process, or connection and returning a true-positive or false-positive verdict, then a
synthesis agent aggregates them. It runs through the Claude Code Workflow tool and is
capped under ten agents. The skill drives this; see `SKILL.md`.

## Output and triage

`findings.tsv` is tab-separated: epoch, severity, layer, category, title, evidence.

Severity: CRIT, HIGH, MED, LOW, INFO. Triage order:

1. Start with CRIT and HIGH. Open the evidence path (read-only) and confirm it is a true
   positive before treating it as real. Check whether it is expected tooling (see
   `allowlist.txt`), a benign file that shares a name, or a leftover test fixture.
2. Correlate across layers. An IOC file plus a matching live network connection plus a
   persistence entry is a confirmed compromise. A lone filename match may be a stale
   artifact.
3. For package IOCs, an installed copy (in `node_modules` or a `dist-info` directory) is
   worse than a lockfile reference.
4. Map confirmed findings to `PATCHES.md` for the fix. For the Oct 2026 credential
   stealers, assume credentials on the host are exposed and rotate them from a clean
   machine; delete payload files; never auto-remediate.

## Layers

1. IOC match (the Oct 2026 wave, from `iocs.tsv`)
2. Persistence
3. Runtime (processes, network, crypto-miner heuristics, correlation-weighted)
4. Package hygiene
5. Posture and optional engines (SIP/Gatekeeper, eMudhra CA, ClamAV, Trivy)
6. Patch posture

## Extending the IOC set

Add rows to `iocs.tsv` (tab-separated: severity, category, match_type, value, note). The
header documents the supported match types: `fname`, `pippkg`, `npmpkg`, `netioc`,
`strioc`, `vsext`. Keep content IOCs high-signal; the engine only greps them in low-risk
files and reports them redacted.

## Tuning false positives

`allowlist.txt` lists expected offensive and development tooling (shell-glob patterns,
matched case-insensitively against process paths and names). Allowlisted hits are moved to
an expected-tooling section instead of being flagged. Edit it per host.

## Validation

Detectors are validated with inert positive-control fixtures: a fake `cook.pth`, a lockfile
pinning the compromised npm versions, a folderOpen-style LaunchAgent, and the Rank Math
fake core file. Build them in a scratch directory and run `scan.sh --root <fixtures>` to
confirm each detector fires before trusting a clean result on a real host. A clean run
alone cannot distinguish "clean" from "broken detector".

## Patch reference

`PATCHES.md` is the vendor-verified October 2026 patch table (fixed versions and official
advisory URLs) plus a list of claims that turned out to be noise or hoaxes, so they are not
chased. It is kept current as vendors ship fixes.

## Limitations

argus is a triage and IOC tool, not a replacement for EDR or a signature antivirus engine.
It finds known indicators, common persistence and miner patterns, and patch gaps. It does
not detect novel, memory-only, or kernel-level implants on its own. Pair confirmed findings
with full incident response, and use `--clamav` or `--trivy` for broader coverage.
