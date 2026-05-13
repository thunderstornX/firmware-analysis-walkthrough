# Firmware samples

This repository ships with one real firmware image as the analysis
target.

## `openwrt-22.03.7-ath79-archer-c7-v2.bin`

| Field | Value |
|---|---|
| Source URL | <https://downloads.openwrt.org/releases/22.03.7/targets/ath79/generic/openwrt-22.03.7-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin> |
| Distribution | OpenWRT |
| Release | 22.03.7 |
| Target | `ath79/generic` (TP-Link Archer C7 v2) |
| Architecture | `mips_24kc` |
| Build revision | `r20341-591b7e93d3` |
| File size | 6,488,389 bytes |
| SHA-256 | `0ca4fe70efe20208bc32b7d636f58226e9f1a872d279dc6a3d05b0f99b677713` |

Verify the checksum against the official OpenWRT `sha256sums` for
the release:

```bash
curl -sSL https://downloads.openwrt.org/releases/22.03.7/targets/ath79/generic/sha256sums \
    | grep tplink_archer-c7-v2-squashfs-sysupgrade.bin
sha256sum samples/openwrt-22.03.7-ath79-archer-c7-v2.bin
```

The image is committed under `samples/` so the entire walkthrough is
reproducible from a single `git clone`. Re-downloading with the URL
above produces the same bytes.
