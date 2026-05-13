"""Unit tests for scripts/cve_correlate.py.

The NVD HTTP client is exercised against locally-fabricated payloads
so the suite is hermetic and runs without network access.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import cve_correlate as cc  # imported via tests/conftest.py path-insert


# ───────────────────────── opkg parser ───────────────────────────

_OPKG_FIXTURE = """\
Package: busybox
Version: 1.35.0-6
Depends: libc, libgcc
Status: install user installed
Section: base
Architecture: mips_24kc
Installed-Time: 1721096410

Package: dropbear
Version: 2022.83-1
Status: install user installed
Section: net
Architecture: mips_24kc

Package: nover-no-version
Status: install user installed
Section: base

Package: dnsmasq
Version: 2.86-13
Section: net
"""


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_parse_opkg_status_skips_records_without_version(tmp_path):
    f = _write(tmp_path, "status", _OPKG_FIXTURE)
    pkgs = cc._parse_opkg_status(f)
    names = [p.name for p in pkgs]
    assert names == ["busybox", "dropbear", "dnsmasq"]
    bb = pkgs[0]
    assert bb.version == "1.35.0-6"
    assert bb.section == "base"


def test_parse_opkg_status_missing_file_returns_empty(tmp_path):
    assert cc._parse_opkg_status(tmp_path / "does_not_exist") == []


# ─────────────────────── version normalisation ───────────────────

@pytest.mark.parametrize("raw, expected", [
    ("1.35.0-6",            "1.35.0"),
    ("2022.83-1",           "2022.83"),
    ("5.15.137-1",          "5.15.137"),
    ("1.1.1u-1",            "1.1.1u"),
    ("2.86-13",             "2.86"),
    ("4.18.0+2024.04.01-1", "4.18.0"),
    ("plainversion",        "plainversion"),
])
def test_normalise_version(raw, expected):
    assert cc._normalise_version(raw) == expected


# ─────────────────────── CPE / cache key helpers ─────────────────

def test_cpe_match_string_shape():
    cpe = cc._cpe_match_string("busybox", "busybox", "1.35.0")
    assert cpe == "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*"


def test_cache_key_is_deterministic_and_short():
    a = cc._cache_key("x", "y", "z")
    b = cc._cache_key("x", "y", "z")
    c = cc._cache_key("x", "y", "Z")
    assert a == b and a != c
    assert len(a) == 16


# ─────────────────────── severity extraction ─────────────────────

def test_severity_from_metrics_prefers_v31():
    m = {
        "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
        "cvssMetricV2":  [{"baseSeverity": "MEDIUM"}],
    }
    assert cc._severity_from_metrics(m) == "critical"


def test_severity_from_metrics_falls_back_to_v2():
    m = {"cvssMetricV2": [{"baseSeverity": "HIGH"}]}
    assert cc._severity_from_metrics(m) == "high"


def test_severity_unknown_when_no_metrics():
    assert cc._severity_from_metrics({}) == "unknown"


def test_english_description_skips_other_locales():
    descs = [
        {"lang": "es", "value": "  ignorame  "},
        {"lang": "en", "value": "   real description  "},
    ]
    assert cc._english_description(descs) == "real description"


# ─────────────────────── NVD client (mocked) ─────────────────────

class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Skip the 6-second NVD politeness sleep during tests."""
    monkeypatch.setattr(cc.time, "sleep", lambda *_a, **_kw: None)


def test_query_nvd_caches_response_to_disk(tmp_path):
    cache_dir = tmp_path / "cache"
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2022-48174",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
                    },
                    "descriptions": [
                        {"lang": "en", "value": "stack overflow in busybox shell"},
                    ],
                    "published": "2023-08-22T20:15:08.690",
                },
            },
        ],
    }
    with patch.object(cc.requests, "get",
                      return_value=_FakeResponse(200, payload)) as mock_get:
        first = cc._query_nvd("busybox", "busybox", "1.35.0",
                              api_key=None, cache_dir=cache_dir)
    assert first == [{
        "id":        "CVE-2022-48174",
        "severity":  "critical",
        "summary":   "stack overflow in busybox shell",
        "published": "2023-08-22T20:15:08.690",
    }]
    assert mock_get.call_count == 1
    # Second call should hit the cache, not the network.
    with patch.object(cc.requests, "get",
                      side_effect=AssertionError("should not hit network")):
        second = cc._query_nvd("busybox", "busybox", "1.35.0",
                               api_key=None, cache_dir=cache_dir)
    assert second == first


def test_query_nvd_404_caches_empty(tmp_path):
    cache_dir = tmp_path / "cache"
    with patch.object(cc.requests, "get", return_value=_FakeResponse(404)):
        out = cc._query_nvd("nopackage", "nope", "0.0",
                            api_key=None, cache_dir=cache_dir)
    assert out == []
    # The empty-result cache file should exist.
    cached = list(cache_dir.glob("*.json"))
    assert len(cached) == 1
    assert json.loads(cached[0].read_text()) == []


def test_query_nvd_passes_api_key_header(tmp_path):
    cache_dir = tmp_path / "cache"
    seen: dict = {}

    def _fake_get(url, params, headers, timeout):  # noqa: ARG001
        seen["headers"] = headers
        return _FakeResponse(200, {"vulnerabilities": []})

    with patch.object(cc.requests, "get", side_effect=_fake_get):
        cc._query_nvd("v", "p", "1", api_key="SECRET",
                      cache_dir=cache_dir)
    assert seen["headers"].get("apiKey") == "SECRET"


# ─────────────────────── findings markdown ───────────────────────

def test_findings_markdown_groups_by_severity():
    pkgs = [
        cc.Package(name="busybox", version="1.35.0-6", cves=[
            {"id": "CVE-2022-48174", "severity": "critical",
             "summary": "stack overflow", "published": "2023-08-22"},
        ]),
        cc.Package(name="dnsmasq", version="2.86-13", cves=[
            {"id": "CVE-2021-45951", "severity": "high",
             "summary": "heap-based bof", "published": "2022-01-19"},
            {"id": "CVE-2021-45952", "severity": "high",
             "summary": "another heap bof", "published": "2022-01-19"},
        ]),
    ]
    md = cc._findings_markdown(pkgs)
    assert "OpenWRT 22.03.7" in md
    assert "**Total CVE matches:** 3" in md
    assert "| critical | 1 |" in md
    assert "| high | 2 |" in md
    assert "CVE-2022-48174" in md
    assert "CVE-2021-45951" in md
    # Pipe in summary must be escaped so the markdown table stays valid.
    bad_pipe_pkg = cc.Package(name="x", version="1", cves=[
        {"id": "CVE-9999-0001", "severity": "low",
         "summary": "a | b | c", "published": "2024-01-01"},
    ])
    md2 = cc._findings_markdown([bad_pipe_pkg])
    assert "a \\| b \\| c" in md2
