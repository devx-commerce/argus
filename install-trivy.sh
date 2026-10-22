#!/usr/bin/env bash
# install-trivy.sh - install a PINNED, checksum-verified Trivy for the argus skill.
# Run this yourself, with permission. argus never calls it automatically.
#
# Pin is deliberate: this month's whole threat theme is poisoned release pipelines,
# so we fetch one exact version and verify its sha256 against the release's own
# checksums file before putting the binary on disk. Override the pin with
# ARGUS_TRIVY_PIN=x.y.z, and the install dir with ARGUS_BIN=/path.
set -euo pipefail

PIN="${ARGUS_TRIVY_PIN:-0.72.0}"
BIN="${ARGUS_BIN:-$HOME/.local/bin}"
REPO="aquasecurity/trivy"

os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) case "$arch" in arm64) asset="macOS-ARM64";; x86_64) asset="macOS-64bit";; *) echo "unsupported arch $arch" >&2; exit 1;; esac;;
  Linux)  case "$arch" in x86_64|amd64) asset="Linux-64bit";; aarch64|arm64) asset="Linux-ARM64";; *) echo "unsupported arch $arch" >&2; exit 1;; esac;;
  *) echo "unsupported OS $os" >&2; exit 1;;
esac

tarball="trivy_${PIN}_${asset}.tar.gz"
base="https://github.com/${REPO}/releases/download/v${PIN}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

echo "argus: fetching Trivy v${PIN} (${asset}) ..."
curl -fsSL "${base}/${tarball}" -o "$work/$tarball"
curl -fsSL "${base}/trivy_${PIN}_checksums.txt" -o "$work/checksums.txt"

echo "argus: verifying sha256 ..."
want="$(grep -E "  ${tarball}\$" "$work/checksums.txt" | awk '{print $1}')"
[ -n "$want" ] || { echo "checksum for $tarball not found in release checksums" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$work/$tarball" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$work/$tarball" | awk '{print $1}')"
fi
if [ "$want" != "$got" ]; then
  echo "CHECKSUM MISMATCH - refusing to install" >&2
  echo "  expected $want" >&2
  echo "  got      $got" >&2
  exit 1
fi

mkdir -p "$BIN"
tar -xzf "$work/$tarball" -C "$work" trivy
install -m 0755 "$work/trivy" "$BIN/trivy"
echo "argus: installed verified Trivy v${PIN} -> $BIN/trivy"
case ":$PATH:" in *":$BIN:"*) : ;; *) echo "note: add $BIN to your PATH to use it (export PATH=\"$BIN:\$PATH\")";; esac
echo "then run: scan.sh --trivy"
