---
name: argus
description: Use when asked to scan this machine (or a teammate's) for malware, viruses, trojans, crypto-miners, backdoors, rootkits, or any sign of compromise; to run a host security sweep or antivirus-style check; to check whether a laptop is infected or compromised; or to hunt the October 2026 supply-chain IOCs (LiteLLM 1.107.0, Tensorlake 0.5.144, SubQuery @subql/common 5.8.3, OVHcloud CLI backdoor, Rank Math PRO 3.0.123) and verify patch posture. Also triggers on "run argus", "scan my laptop", "am I compromised", "check for crypto mining", "malware scan".
---

# argus - host compromise and malware triage

argus is a read-only, multi-layer host scanner for macOS and Linux. A deterministic
Bash engine (scan.sh) does the detection; you (the model) triage its output. It is
tuned for the October 2026 supply-chain / credential-theft wave and for general
host-compromise, persistence, crypto-miner, and patch-posture checks.

## Safety contract (never weaken)

- Read-only. argus never deletes, kills, quarantines, chmods, or installs anything.
- It never executes a possibly-compromised artifact. Suspect package versions are read
  from the filesystem, never by running pip / npm / the vendor CLI. Any python it runs
  uses `-I -S` so .pth / sitecustomize payloads cannot load.
- It never phones home. All IOC matching is local. (Exceptions are opt-in and explicit:
  `--trivy` fetches Trivy's vuln DB; `--clamav` uses a local engine.)
- It redacts matched content (reports file:line + which IOC, not the line text), so it
  does not spill secrets from history or .env files into the report.
- Remediation is your job to recommend and the operator's to approve. Do not act on
  findings without explicit approval, per the operator's standing rule.

## How to run

```
scan.sh                 # default: read-only, fully local, macOS or Linux
scan.sh --trivy         # also run pinned Trivy (CRITICAL only); needs install-trivy.sh first
scan.sh --clamav        # also run ClamAV if already installed (never installs it)
scan.sh --root DIR      # scan only DIR (filesystem layers); used for positive-control tests
scan.sh --quiet         # summary to terminal; full report still written to the out dir
```

The script prints a summary and writes `findings.tsv` and `report.txt` to a temp out dir
(path printed at the end). Exit code: 0 clean/info-only, 1 any HIGH, 2 any CRIT.

Trivy is pinned (default v0.72.0) and checksum-verified. argus never auto-installs it;
run `install-trivy.sh` yourself (it verifies sha256 against the release checksums file).

## Layers

1. IOC match - the Oct 2026 wave, from `iocs.tsv` (filenames, dist-info dirs, npm
   lockfile/node_modules versions, C2 IPs/domains, crypto wallet, malicious editor
   extension). LiteLLM sitecustomize.py is only flagged when it sits beside cook.*.
2. Persistence - launchd (macOS) / systemd + cron + rc + ld.so.preload (Linux), shell-rc
   pipe-to-shell droppers, authorized_keys changes, UID 0 accounts, third-party kexts.
3. Runtime - processes, two CPU samples for sustained load, exec paths in temp/hidden
   dirs, miner process names, listening sockets, established connections to mining-pool
   ports or known IOC IPs, Linux deleted-exe detection. Signals are correlation-weighted
   (two+ signals on one pid escalates to CRIT) to survive a pentester's toolbox.
4. Package hygiene - unusual python .pth startup hooks, editor-extension inventory.
5. Posture + engines - SIP/Gatekeeper (macOS), emSign/eMudhra CA presence, optional
   ClamAV, optional Trivy (CRITICAL).
6. Patch posture - Node / Go / Tailscale / PHP versions vs the Oct 2026 fixes, and any
   local WordPress UpdraftPlus / Rank Math / Bricksforge trees. See PATCHES.md.

An allowlist (`allowlist.txt`) moves expected offensive/dev tooling into its own section
instead of flagging it. Edit it per host.

## How to triage the output

Read `findings.tsv` (tab-separated: epoch, severity, layer, category, title, evidence).

- CRIT / HIGH first. For each, confirm it is a true positive before telling the operator
  it is real: open the evidence path (read-only), check whether it is allowlisted tooling,
  a test fixture, or a benign file that shares a name. State the failure scenario concretely.
- Correlate across layers: an IOC file plus a matching live network connection plus a
  persistence entry is a confirmed compromise; a lone filename match may be a stale artifact.
- For package IOCs, "INSTALLED" (node_modules/dist-info on disk) is worse than "in lockfile".
- Map confirmed findings to PATCHES.md for the fix, and to the Oct 2026 remediation (for
  LiteLLM/Tensorlake/SubQuery/OVHcloud: assume creds on that host are exposed and advise
  rotation from a clean machine; deletion of payload files; never auto-remediate).
- Report with the exact command run and the raw evidence. Do not paraphrase findings.
- Recommend; do not execute. Ask before any change.

## Deep mode

`--deep` is driven here, not by scan.sh. After a normal scan, when the operator asks to
go deep (or there are several unresolved HIGH/CRIT findings), run the Workflow in
`deep-mode.workflow.js`: it fans out one investigator agent per flagged anomaly (capped),
each gathering read-only context on that file/process/connection and returning a
true-positive / false-positive verdict with evidence, then aggregates. Pass the findings
TSV path as the workflow arg. Keep it to the HIGH/CRIT findings; do not fan out on INFO.

## Maintenance

- Add new IOCs to `iocs.tsv` (one per line; the header documents the match types).
- Update `PATCHES.md` as vendors ship fixes; update `TRIVY_PIN` in scan.sh when you bump
  the pinned Trivy (and re-run install-trivy.sh).
- Re-validate detectors after edits with the positive-control fixtures (see the repo's
  self-test: build inert fixtures, run `scan.sh --root <fixtures>`, confirm each fires).
