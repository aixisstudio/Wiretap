"""
EN: Unit tests for the DNS filtering proxy (detection/dnsfw.py).
FR: Tests unitaires du proxy DNS filtrant (detection/dnsfw.py).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.dnsfw import (DnsFirewall, DomainFilter, _parse_hosts,
                             build_nxdomain, parse_qname, parse_qtype)


def _query(name: str, qtype: int = 1) -> bytes:
    """EN: Build a minimal wire-format query for `name`. FR: idem."""
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + q + struct.pack("!HH", qtype, 1)


def test_parse_qname_simple():
    assert parse_qname(_query("example.com")) == "example.com"
    assert parse_qname(_query("a.b.c.example.org")) == "a.b.c.example.org"


def test_parse_qname_malformed():
    assert parse_qname(b"\x00" * 5) is None
    assert parse_qname(b"") is None
    # EN: compression pointer inside the question = invalid query / FR: pointeur invalide
    pkt = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00" + struct.pack("!HH", 1, 1)
    assert parse_qname(pkt) is None


def test_parse_qtype():
    assert parse_qtype(_query("x.com", 28)) == 28
    assert parse_qtype(_query("x.com", 1)) == 1


def test_nxdomain_flags_and_question():
    q = _query("ads.example.com")
    resp = build_nxdomain(q)
    assert resp[:2] == q[:2]                        # EN: same txid / FR: même txid
    flags = struct.unpack("!H", resp[2:4])[0]
    assert flags & 0x8000                           # QR = response
    assert flags & 0x000F == 3                      # RCODE = NXDOMAIN
    assert struct.unpack("!H", resp[6:8])[0] == 0   # ANCOUNT = 0
    assert b"ads" in resp                           # EN: question preserved / FR: question préservée


def test_filter_suffix_matching():
    f = DomainFilter()
    f.add("doubleclick.net", "ads_trackers")
    assert f.verdict("doubleclick.net") == "ads_trackers"
    assert f.verdict("ad.doubleclick.net") == "ads_trackers"
    assert f.verdict("deep.sub.ad.doubleclick.net") == "ads_trackers"
    assert f.verdict("notdoubleclick.net") is None
    assert f.verdict("doubleclick.net.evil.com") is None


def test_filter_whitelist_wins():
    f = DomainFilter()
    f.add("example.com", "ads_trackers")
    f.whitelist_add("good.example.com")
    assert f.verdict("example.com") == "ads_trackers"
    assert f.verdict("good.example.com") is None
    assert f.verdict("sub.good.example.com") is None
    f.whitelist_remove("good.example.com")
    assert f.verdict("good.example.com") == "ads_trackers"


def test_parse_hosts_format():
    text = """# comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net # trailing comment
127.0.0.1 localhost
::1 ip6-localhost
not-an-ip-line
"""
    out = _parse_hosts(text, "hosts")
    assert "ads.example.com" in out
    assert "tracker.example.net" in out
    assert "localhost" not in out


def test_parse_domains_format_urls():
    text = """http://phish.example.com/login/path
https://evil.example.org/x
bare-domain.example.net
not a domain line!
"""
    out = _parse_hosts(text, "domains")
    assert "phish.example.com" in out
    assert "evil.example.org" in out
    assert "bare-domain.example.net" in out
    assert len(out) == 3


def test_configure_drops_invalid():
    fw = DnsFirewall(Path("/tmp/x"))
    st = fw.configure(categories=["ads_trackers", "bogus_cat"],
                      upstream_mode="quad9", bind_port=5353)
    assert st["categories"] == ["ads_trackers"]
    assert st["upstream_mode"] == "quad9"
    fw.configure(upstream_mode="not-a-mode")
    assert fw.upstream_mode == "quad9"          # EN: unchanged / FR: inchangé


def test_status_shape():
    fw = DnsFirewall(Path("/tmp/x"))
    st = fw.status()
    for key in ("running", "bind", "upstream_mode", "categories",
                "available_categories", "domains_loaded", "stats", "per_category"):
        assert key in st
    assert "ads_trackers" in st["available_categories"]
    assert st["running"] is False
