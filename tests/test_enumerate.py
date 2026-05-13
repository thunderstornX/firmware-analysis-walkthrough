"""Unit tests for scripts/enumerate.py.

We synthesize a tiny pseudo-root in tmp_path containing files that
should trip a known subset of the pattern scanner, and confirm that
the scanner picks them up — and that the tree renderer caps depth.
"""
from __future__ import annotations

from pathlib import Path

import enumerate as enum_mod  # via tests/conftest.py path-insert


def _make_fake_root(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "config").mkdir()
    (root / "etc" / "passwd").write_text("root::0:0:root:/root:/bin/ash\n")
    (root / "etc" / "config" / "network.conf").write_text(
        "password = hunter2\n"
        "admin: admin\n"
        "url = http://example.local/api\n"
    )
    (root / "etc" / "ssh_host_key.pem").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "abc...\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "bin" / "boot.sh").write_text(
        "#!/bin/sh\nbusybox telnetd -l /bin/sh &\n"
    )
    (root / "etc" / "tokens.json").write_text(
        '{ "api_key": "AKIA1234567890abcdef" }\n'
    )
    # Random binary blob the scanner should leave alone.
    (root / "usr" / "bin" / "blob.bin").write_bytes(b"\x00\x01\x02" * 4096)
    return root


def test_scan_patterns_finds_each_category(tmp_path):
    root = _make_fake_root(tmp_path)
    hits = enum_mod._scan_patterns(root)

    assert any(h["path"].endswith("ssh_host_key.pem")
               for h in hits["private_key_header"])
    assert any(h["path"].endswith("network.conf")
               for h in hits["password_assignment"])
    assert any(h["path"].endswith("boot.sh")
               for h in hits["hardcoded_telnet"])
    assert any(h["path"].endswith("network.conf")
               for h in hits["hardcoded_url_http"])
    assert any(h["path"].endswith("network.conf")
               for h in hits["default_admin_login"])
    assert any(h["path"].endswith("passwd")
               for h in hits["root_passwd_blank"])
    assert any(h["path"].endswith("tokens.json")
               for h in hits["api_token_like"])


def test_walk_text_files_skips_binary_blobs(tmp_path):
    root = _make_fake_root(tmp_path)
    text_files = list(enum_mod._walk_text_files(root))
    # blob.bin has no whitelisted text-glob extension, so it must be
    # excluded — otherwise we'd waste cycles binary-grepping it.
    assert not any(p.name == "blob.bin" for p in text_files)
    # passwd is a known no-extension config and must be included.
    assert any(p.name == "passwd" for p in text_files)


def test_render_tree_respects_depth_cap(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_text("x\n")
    tree = enum_mod._render_tree(tmp_path, max_depth=2)
    # Depth 0 = tmp_path itself; depth 1 = 'a/'; depth 2 = stop.
    assert "a/" in tree
    assert "leaf.txt" not in tree
