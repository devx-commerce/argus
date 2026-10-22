# October 2026 patch reference (argus)

Verified against vendor CNA records (cveawg.mitre.org), vendor PSIRT/advisory pages, and
package registries as of 2026-10-22. Public web search lags these fresh advisories badly, so
the official URLs below are the source of truth. Confirm per-branch build strings on the
vendor page for appliance products (Ivanti / Ahsay / SonicWall / Palo Alto).

## Fixed versions

| Item | CVE(s) | Fixed version | Official advisory |
|------|--------|---------------|-------------------|
| PHP core RCE ("php2shell") | CVE-2026-109618, CVE-2026-109619 | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w , GHSA-6wmf-4rv5-p3rp |
| Node.js Oct 2026 (incl. Brotli RCE CVE-2026-111497 + eMudhra CA) | CVE-2026-105482/105483/106069/111497 (+ med/low) | 22.23.4 / 24.22.1 / 26.12.1 | nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| Go crypto/x509 (eMudhra) | CVE-2026-111943 (GO-2026-6809) | go1.27.3 / go1.26.10 | groups.google.com/g/golang-announce/c/66pojueaQek , pkg.go.dev/vuln/GO-2026-6809 |
| Tailscale (eMudhra) | TS-2026-013 (no CVE) | v1.104.2 | tailscale.com/security-bulletins (ts-2026-013) |
| GitLab CE/EE regex RCE | CVE-2026-97229 (10.0) | 19.4.2 / 19.3.5 / 19.2.8 (19.3.4 still vulnerable) | docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released |
| Bricksforge (WP) | CVE-2026-85097 | 3.1.8.10 (3.x) / 4.0.2 (4.x) | wordfence.com/threat-intel/vulnerabilities/id/e993c929-... ; bricksforge.io/version-changelog |
| Ivanti Connect Secure | CVE-2026-104935 | 22.8R2.5 / 25.1.1.2 / 25.1.3.x | hub.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935 |
| BeyondTrust Remote Support | CVE-2026-102764 (9.3) | 26.2.4, or patch BT26-05-RS | beyondtrust.com/blog/entry/bt26-05 |
| Atlassian Data Center (8 products) | CVE-2026-21589 (9.3) | Jira 9.12.40/10.3.26/11.3.12; Confluence 9.2.26/10.2.19; Bitbucket 9.4.26/10.2.8/10.5.1; Bamboo 10.2.24/12.1.12; Crowd 6.3.7/7.0.3/7.1.7/7.2.4; Crucible/Fisheye 4.9.15 | jira.atlassian.com/browse/JRASERVER-79546 (+ per-product tickets) |
| Palo Alto PAN-OS mgmt RCE | CVE-2026-0322 (8.6) | 12.2.4; 12.1.x/11.2.x/11.1.x/10.2.x hotfixes | security.paloaltonetworks.com/CVE-2026-0322 |
| Cisco Secure Email Gateway | CVE-2026-76519 | Content Scanner Tools 25.3.0.5525+ (AsyncOS 15.5.5-014 / 16.5.0-780) | sec.cloudapps.cisco.com/.../cisco-sa-esa-afw-zqYJkjxp |
| Ahsay AhsayCBS unauth RCE | CVE-2026-105133, CVE-2026-105134 | v10.3.4.45 / v9.15.2.70 hotfix | ahsay.com/en/support/help-centre/release-notes/cbs/v10.3.4 |
| SonicWall SMA1000 pre-auth SSRF | CVE-2026-102255 (10.0) | 12.4.3 / 12.5.0 hotfix (per PSIRT) | psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0017 |
| Oracle CPU Oct 2026 (1283 patches; APEX 9.8) | multiple | per product | oracle.com/security-alerts/cpuoct2026.html |
| Fortinet FortiSIEM gRPC RCE | CVE-2026-106173 | 7.5.1+ | fortiguard.fortinet.com/psirt/FG-IR-26-180 |
| Fortinet FortiSandbox auth bypass | CVE-2026-107656 | 5.0.7+ / 4.4.10+ | fortiguard.fortinet.com/psirt/FG-IR-26-185 |
| Rank Math PRO backdoor | CVE-2026-111862 (9.8) | 3.0.124 | rankmath.com/kb/pro-3-0-123-security-incident |
| OVHcloud CLI compromised binaries | GHSA-862f-55f5-vmvw (no CVE) | 0.16.0 (vendor-confirmed unaffected) | github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw |

## Compromised packages - roll to the safe version

| Package | Bad | Safe | Note |
|---------|-----|------|------|
| litellm (PyPI) | 1.107.0 | 1.106.2 | malicious 1.107.0 live ~2h on 2026-10-21; delete cook.pth/cook.py/sitecustomize.py, rotate creds |
| tensorlake (npm) | 0.5.144 | 0.5.143 | Shai-Hulud/ChainDrop worm; latest clean is now 0.5.158 |
| @subql/common (npm) | 5.8.3 | 5.8.2 | no clean release AFTER 5.8.3; npm `latest` points back to 5.8.2 - roll back |
| OVHcloud CLI | backdoored binaries (served 14:47-16:21 CEST 2026-10-19) | 0.16.0 | binary swap, not source; rotate on-disk secrets if a bad binary ran |
| Rank Math PRO (WP) | 3.0.123 | 3.0.124 | updating alone does NOT clean; hunt rogue admins/dropped files |

## Do NOT act on these (noise / debunked)

- CVE-2026-91403 "Java JSSE 9.1 RCE": fabricated. No such CVE; version strings are not real Oracle trains. Real 2026 JSSE flaws are low/medium (CVE-2026-46968 5.9, CVE-2026-70907 5.3).
- PingCAP / TiDB Cloud "Oct 2026 incident": no evidence found anywhere.
- "iPhone 11-16 remote access": exaggeration of the real but September item CVE-2026-86950 (CoreGraphics, iOS 26.7.1, narrowly targeted).
- GhostAction: real but misdated - it was September 2025, not October 2026.
- SBI (~375k records) and Rajasthan Police (~70k records) "leaks": unverified BreachForums sale listings, not acknowledged breaches.

## Not a patch - a trust action (eMudhra)

Eight eMudhra intermediate CA private keys were recoverable (weak key generation, not a hack).
Browsers auto-blocked them. Residual risk is non-browser TLS clients that skip revocation
(Python, Ruby, Go, Node, macOS /usr/bin/curl). Update language runtimes (Node/Go above) and OS
CA bundles. argus flags emSign presence in the keychain / system bundle as a reminder.
