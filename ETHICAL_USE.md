# Ethical Use Policy

This repository analyses a publicly distributed OpenWRT release
image. All findings are surfaced against a published release for
which the upstream project encourages community testing; no
unpublished or proprietary firmware is touched.

## Scope

- Educational and research analysis of public router firmware.
- Reproducing the walkthrough against another publicly distributed
  image for which the operator has the legal right to analyse.
- Internal product-security audits where the operator builds or
  procures the firmware they are analysing.
- Capture-the-flag and training environments.

## Out of scope

- Analysing a firmware image extracted from a device you do not own.
- Pre-disclosure analysis of proprietary firmware obtained outside of
  an authorised research agreement.
- Using extracted credentials or keys against live infrastructure.
- Targeting individuals or specific deployed devices.

## Responsible disclosure

If a previously unknown vulnerability is identified in the upstream
project, follow OpenWRT's security policy at
<https://openwrt.org/about/security> before any public discussion.
Vulnerabilities surfaced from already-published CVEs (which is the
case for everything in `results/findings.md`) do not require
disclosure — they are already public.

## Attribution

The walkthrough relies on:

- **binwalk** (ReFirmLabs) — signature scanner.
  <https://github.com/ReFirmLabs/binwalk>
- **firmwalker** (Craig Heffner / craigz28) — filesystem pattern scan.
  <https://github.com/craigz28/firmwalker>
- **Ghidra** (National Security Agency) — binary analysis platform.
  <https://github.com/NationalSecurityAgency/ghidra>
- **squashfs-tools** (Phillip Lougher) — `unsquashfs`.
- **OpenWRT** — the analysed firmware.
  <https://openwrt.org>

These projects carry their own licences; this repository's MIT
licence governs only the walkthrough scripts, tests, documentation,
and paper.
