# Security Policy

argus is a read-only security tool. Its core guarantee is that it never changes the host,
never executes a scanned artifact, and never sends data off the machine.

## Reporting a vulnerability

If you find a security issue in argus itself (for example, a way to make it write, execute,
or exfiltrate), report it privately:

- Preferred: use GitHub private vulnerability reporting on this repository
  (Security tab, then "Report a vulnerability").
- Do not open a public issue or pull request for a security vulnerability.

We aim to acknowledge reports within three business days.

## Scope

In scope: the scanner engine (scan.sh), the installer, the deep-mode workflow, the IOC and
patch data, and anything that could cause argus to break its read-only contract.

Out of scope: false positives or missed detections (please open a normal issue), and
vulnerabilities in third-party tools argus can invoke, such as ClamAV or Trivy (report those
to their maintainers).

## Design invariant

argus must stay read-only. Any change that lets it delete, modify, execute a scanned
artifact, or send data off the host is treated as a security regression. See the README for
the full safety contract.
