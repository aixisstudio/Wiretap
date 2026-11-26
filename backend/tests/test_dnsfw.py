"""
EN: Unit tests for the DNS filtering proxy (detection/dnsfw.py).
FR: Tests unitaires du proxy DNS filtrant (detection/dnsfw.py).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection import dnsfw
from detection.dnsfw import (
    DnsFirewall,
    DomainFilter,
    _parse_hosts,
    build_nxdomain,
    parse_qname,
    parse_qtype,
)


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


# ── Filter-list presets / Préréglages de listes ─────────────────────────────

# EN: shape of the NetAPI list: bare domains, one per line (a `#` line is
#     tolerated in case a header is ever added).
# FR: forme de la liste NetAPI : domaines nus, un par ligne (une ligne `#`
#     est tolérée au cas où un en-tête serait ajouté).
SAMPLE_NETAPI_DOMAINS = """# NetAPI.com - compromised domains (CC BY 4.0)
phish-login.example.com
fake-shop.example.org
PHISH-LOGIN.example.com

not a domain line!
"""


class _FakeResponse:
    """EN: Minimal stand-in for the urlopen() context manager. FR: idem."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]


def _fake_urlopen(calls: list[str], body: str):
    def _open(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResponse(body.encode())
    return _open


def test_no_preset_uses_retired_urlhaus_hostfile():
    """EN: abuse.ch retired its keyless downloads on 2026-10-21 (HTTP 410).
    The UI offers a checkbox only, so a preset that needs a key loads nothing.
    FR: abuse.ch a retiré ses téléchargements sans clé le 2026-10-21 (HTTP
    410). L'UI ne propose qu'une case à cocher : un préréglage qui exige une
    clé ne charge rien."""
    assert "malware_abusech" not in dnsfw.LIST_PRESETS
    for key, preset in dnsfw.LIST_PRESETS.items():
        assert preset["url"].startswith("https://"), key
        assert "abuse.ch" not in preset["url"], key


def test_netapi_preset_registered():
    """EN: Preset metadata + exposure in status(). FR: Métadonnées du
    préréglage + exposition dans status()."""
    p = dnsfw.LIST_PRESETS["malicious_netapi"]
    assert p["url"] == "https://netapi.com/api2/netapi-compromised-domains-short.txt"
    assert p["format"] == "domains"
    assert p["license"] == "CC BY 4.0"
    assert "NetAPI" in p["label"]
    st = DnsFirewall(Path("/tmp/x")).status()
    assert st["available_categories"]["malicious_netapi"] == p["label"]


def test_netapi_list_shape_parses():
    """EN: Comment, blank and junk lines are dropped, domains are kept.
    FR: Commentaire, lignes vides et bruit écartés, domaines conservés."""
    out = _parse_hosts(SAMPLE_NETAPI_DOMAINS, "domains")
    assert out == ["phish-login.example.com", "fake-shop.example.org",
                   "PHISH-LOGIN.example.com"]


def test_refresh_lists_netapi_preset_fetch_then_cache(monkeypatch, tmp_path):
    """EN: Enabling the category fetches the preset URL once, blocks the
    listed names (and their subdomains), and the next refresh is served
    from the on-disk cache without a second request.
    FR: Activer la catégorie récupère l'URL du préréglage une fois, bloque
    les noms listés (et leurs sous-domaines), et le refresh suivant est
    servi depuis le cache disque sans seconde requête."""
    calls: list[str] = []
    monkeypatch.setattr(dnsfw.urllib.request, "urlopen",
                        _fake_urlopen(calls, SAMPLE_NETAPI_DOMAINS))
    fw = DnsFirewall(tmp_path)
    fw.configure(categories=["malicious_netapi"])

    res = fw.refresh_lists()
    assert calls == [dnsfw.LIST_PRESETS["malicious_netapi"]["url"]]
    assert res["report"]["malicious_netapi"].startswith("fetched 3 domains")
    assert res["domains_loaded"] == 2            # EN: case-folded duplicate / FR: doublon de casse
    assert fw.filter.verdict("phish-login.example.com") == "malicious_netapi"
    assert fw.filter.verdict("www.fake-shop.example.org") == "malicious_netapi"
    assert fw.filter.verdict("example.com") is None

    res = fw.refresh_lists()
    assert len(calls) == 1                       # EN: no second fetch / FR: pas de second fetch
    assert res["report"]["malicious_netapi"] == "cache (3 domains)"
    assert res["domains_loaded"] == 2


def test_saved_retired_category_is_dropped_not_migrated(monkeypatch, tmp_path):
    """EN: A saved "malware_abusech" choice was consent for abuse.ch only:
    it is dropped, no other host is contacted in its place.
    FR: Un choix "malware_abusech" enregistré valait consentement pour
    abuse.ch seulement : il est écarté, aucun autre hôte n'est contacté à
    sa place."""
    calls: list[str] = []
    monkeypatch.setattr(dnsfw.urllib.request, "urlopen",
                        _fake_urlopen(calls, SAMPLE_NETAPI_DOMAINS))
    fw = DnsFirewall(tmp_path)
    st = fw.configure(categories=["malware_abusech"])
    assert st["categories"] == []
    res = fw.refresh_lists()
    assert calls == []
    assert res == {"report": {}, "domains_loaded": 0}
