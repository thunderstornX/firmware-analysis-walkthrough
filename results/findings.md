# CVE correlation findings

Source firmware: OpenWRT 22.03.7 (ath79/generic, mips_24kc).

**Total CVE matches:** 16

| Severity | Count |
|---|---:|
| critical | 8 |
| high | 5 |
| medium | 2 |
| low | 1 |
| unknown | 0 |

## Critical (8)

| Package | Version | CVE | Published | Summary |
|---|---|---|---|---|
| `busybox` | `1.35.0-5` | [CVE-2022-48174](https://nvd.nist.gov/vuln/detail/CVE-2022-48174) | 2023-08-22 | There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35. In the environment of Internet of Vehic… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45951](https://nvd.nist.gov/vuln/detail/CVE-2021-45951) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in check_bad_address (called from check_for_bogus_wildcard and FuzzChec… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45952](https://nvd.nist.gov/vuln/detail/CVE-2021-45952) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in dhcp_reply (called from dhcp_packet and FuzzDhcp). NOTE: the vendor'… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45953](https://nvd.nist.gov/vuln/detail/CVE-2021-45953) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in extract_name (called from hash_questions and fuzz_util.c). NOTE: the… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45954](https://nvd.nist.gov/vuln/detail/CVE-2021-45954) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in extract_name (called from answer_auth and FuzzAuth). NOTE: the vendo… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45955](https://nvd.nist.gov/vuln/detail/CVE-2021-45955) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in resize_packet (called from FuzzResizePacket and fuzz_rfc1035.c) beca… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45956](https://nvd.nist.gov/vuln/detail/CVE-2021-45956) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in print_mac (called from log_packet and dhcp_reply). NOTE: the vendor'… |
| `dnsmasq` | `2.86-16` | [CVE-2021-45957](https://nvd.nist.gov/vuln/detail/CVE-2021-45957) | 2022-01-01 | Dnsmasq 2.86 has a heap-based buffer overflow in answer_request (called from FuzzAnswerTheRequest and fuzz_rfc1035.c)… |

## High (5)

| Package | Version | CVE | Published | Summary |
|---|---|---|---|---|
| `busybox` | `1.35.0-5` | [CVE-2022-28391](https://nvd.nist.gov/vuln/detail/CVE-2022-28391) | 2022-04-03 | BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record… |
| `busybox` | `1.35.0-5` | [CVE-2022-30065](https://nvd.nist.gov/vuln/detail/CVE-2022-30065) | 2022-05-18 | A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution when processin… |
| `dnsmasq` | `2.86-16` | [CVE-2022-0934](https://nvd.nist.gov/vuln/detail/CVE-2022-0934) | 2022-08-29 | A single-byte, non-arbitrary write/use-after-free flaw was found in dnsmasq. This flaw allows an attacker who sends a… |
| `dnsmasq` | `2.86-16` | [CVE-2023-28450](https://nvd.nist.gov/vuln/detail/CVE-2023-28450) | 2023-03-15 | An issue was discovered in Dnsmasq before 2.90. The default maximum EDNS.0 UDP packet size was set to 4096 but should… |
| `dnsmasq` | `2.86-16` | [CVE-2023-50387](https://nvd.nist.gov/vuln/detail/CVE-2023-50387) | 2024-02-14 | Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers t… |

## Medium (2)

| Package | Version | CVE | Published | Summary |
|---|---|---|---|---|
| `busybox` | `1.35.0-5` | [CVE-2025-60876](https://nvd.nist.gov/vuln/detail/CVE-2025-60876) | 2025-11-10 | BusyBox wget thru 1.3.7 accepted raw CR (0x0D)/LF (0x0A) and other C0 control bytes in the HTTP request-target (path/… |
| `dropbear` | `2022.82-4` | [CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) | 2023-12-18 | The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows re… |

## Low (1)

| Package | Version | CVE | Published | Summary |
|---|---|---|---|---|
| `busybox` | `1.35.0-5` | [CVE-2025-46394](https://nvd.nist.gov/vuln/detail/CVE-2025-46394) | 2025-04-23 | In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal … |

