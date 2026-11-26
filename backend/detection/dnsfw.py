"""
EN: DNS firewall — a local filtering DNS proxy. Point the system (or one
    app, or a whole LAN) at Wiretap instead of the ISP resolver and every
    lookup passes through here:

      * BLOCK — domains matching enabled filter-list categories (ads,
        trackers, malware, phishing…) get NXDOMAIN. The connection never
        starts: no IP, no TLS, no beacon. This is prevention, not
        detection — the layer Wiretap was missing against Portmaster.
      * FORWARD — everything else is relayed verbatim to the upstream:
        the system resolver (plaintext UDP) or an encrypted DNS-over-HTTPS
        endpoint (Cloudflare / Quad9 / Google / custom), which also hides
        the queries from the ISP.
      * OBSERVE — every blocked name lands in a bounded ring buffer with
        counters per category, exposed on /dnsfw/*. The graph already
        shows who connects out; this shows what we refused.

    Honest boundaries: this is a proxy, not a MITM. It cannot see inside
    apps that use their own hardcoded DoH (Chrome sometimes does) — those
    bypass any resolver. Binding :53 needs admin/root, so the default is
    127.0.0.1:5353 and the docs explain the one-time system DNS change.
    Filter lists are opt-in outbound fetches, cached on disk, refreshed
    at most once a day, bounded in size, and each fetch reports exactly
    what it did (see detection/blocklist.py for the same policy).

    No third-party DNS library: the wire-format parsing below is the
    complete minimal subset (header + question QNAME) needed to filter
    and relay, consistent with the project's own-parsers rule.

FR: Pare-feu DNS — un proxy DNS filtrant local. Pointer le système (ou
    une app, ou tout un LAN) vers Wiretap au lieu du résolveur du FAI et
    chaque requête passe ici :

      * BLOCAGE — les domaines des catégories de listes activées (pubs,
        trackers, malware, phishing…) reçoivent NXDOMAIN. La connexion ne
        démarre jamais : pas d'IP, pas de TLS, pas de beacon. C'est de la
        prévention, pas de la détection — la couche qui manquait à
        Wiretap face à Portmaster.
      * RELAIS — tout le reste est transmis verbatim à l'amont : le
        résolveur système (UDP clair) ou un endpoint DNS-over-HTTPS
        chiffré (Cloudflare / Quad9 / Google / personnalisé), ce qui
        masque aussi les requêtes au FAI.
      * OBSERVATION — chaque nom bloqué part dans un anneau borné avec
        compteurs par catégorie, exposé sur /dnsfw/*.

    Bornes honnêtes : c'est un proxy, pas un MITM. Les apps avec DoH
    codé en dur contourneront toujours tout résolveur. Binder :53 exige
    admin/root, donc le défaut est 127.0.0.1:5353 et la doc explique le
    changement DNS système (une fois). Les listes sont des fetches opt-in
    cachés sur disque, bornés, rafraîchis au plus une fois par jour.

    Aucune lib DNS tierce : le parsing wire-format ci-dessous est le
    sous-ensemble minimal complet (en-tête + QNAME) pour filtrer et
    relayer, conforme à la règle parseurs-maison du projet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import struct
import threading
import time
import urllib.request
from pathlib import Path

logger = logging.getLogger("wiretap.dnsfw")

# ── Curated filter-list presets / Préréglages de listes ─────────────────────
# EN: public lists, hosts format (0.0.0.0 domain per line) or bare domains
#     ("format": "domains"). Licenses are redistribution-friendly
#     (StevenBlack: MIT; NetAPI: CC BY 4.0). Sizes are enforced at fetch
#     time (4 MiB cap, same policy as blocklist.py). Every URL here must
#     answer without an account or key: the UI offers a checkbox only.
# FR: listes publiques, format hosts ou domaines nus ("format": "domains").
#     Licences compatibles redistribution (StevenBlack : MIT ; NetAPI :
#     CC BY 4.0). Tailles bornées au fetch (4 Mio). Chaque URL doit
#     répondre sans compte ni clé : l'UI ne propose qu'une case à cocher.
LIST_PRESETS: dict[str, dict] = {
    "ads_trackers": {
        "label": "Ads & trackers (StevenBlack unified)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "license": "MIT",
    },
    # EN: replaces "malware_abusech" (URLhaus hostfile): abuse.ch retired its
    #     keyless downloads on 2026-10-21 and that URL answers HTTP 410, so
    #     the category loaded nothing. NetAPI list without sinkholed names:
    #     phishing and scam sites, regenerated hourly, no key. The key is
    #     new on purpose: a saved "malware_abusech" choice is dropped by
    #     configure(), never moved to another host without a fresh opt-in.
    # FR: remplace "malware_abusech" (hostfile URLhaus) : abuse.ch a retiré
    #     ses téléchargements sans clé le 2026-10-21 et cette URL répond
    #     HTTP 410, la catégorie ne chargeait donc rien. Liste NetAPI sans
    #     les noms en sinkhole : sites de phishing et d'arnaque, régénérée
    #     chaque heure, sans clé. La clé est nouvelle exprès : un choix
    #     "malware_abusech" enregistré est écarté par configure(), jamais
    #     déplacé vers un autre hôte sans nouvel opt-in.
    "malicious_netapi": {
        "label": "Malicious domains: phishing & scams (NetAPI)",
        "url": "https://netapi.com/api2/netapi-compromised-domains-short.txt",
        "license": "CC BY 4.0",
        "format": "domains",
    },
    "phishing_openphish": {
        "label": "Phishing (OpenPhish community)",
        "url": "https://openphish.com/feed.txt",
        "license": "community",
        "format": "domains",  # EN: bare domains, one per line / FR: domaines nus
    },
    "gambling": {
        "label": "Gambling (StevenBlack extension)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
        "license": "MIT",
    },
    "social": {
        "label": "Social media (StevenBlack extension)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
        "license": "MIT",
    },
    "nsfw": {
        "label": "Adult content (StevenBlack extension)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
        "license": "MIT",
    },
    "fakenews_crypto": {
        "label": "Fake news & crypto scams (StevenBlack ext.)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
        "license": "MIT",
    },
}

# EN: DoH upstream presets — wireformat POST endpoints, no account needed.
# FR: Préréglages amont DoH — endpoints POST wireformat, sans compte.
DOH_PRESETS: dict[str, str] = {
    "cloudflare": "https://1.1.1.1/dns-query",
    "cloudflare_family": "https://family.cloudflare-dns.com/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
    "google": "https://dns.google/dns-query",
}

_MAX_LIST_BYTES = 4 * 1024 * 1024
_FETCH_TIMEOUT = 15.0
_REFRESH_INTERVAL = 24 * 3600        # EN: at most daily / FR: au plus quotidien
_MAX_BLOCKED_LOG = 500               # EN: ring size / FR: taille de l'anneau
_MAX_DOMAINS = 400_000               # EN: memory guard / FR: garde mémoire
_DNS_PORT = 53


# ── Wire-format helpers / Helpers wire-format ───────────────────────────────

def parse_qname(packet: bytes) -> str | None:
    """EN: Extract the first question's QNAME from a DNS query packet.
    Returns the lowercased dotted name without trailing dot, or None if
    the packet is malformed. Compression pointers cannot appear inside a
    question of a query, so plain label walking is enough.
    FR: Extrait le QNAME de la première question d'une requête DNS.
    Compression impossible dans une question de requête — le parcours de
    labels simple suffit."""
    try:
        if len(packet) < 13:
            return None
        qdcount = struct.unpack("!H", packet[4:6])[0]
        if qdcount < 1:
            return None
        pos = 12
        labels: list[str] = []
        while pos < len(packet):
            ln = packet[pos]
            if ln == 0:
                break
            if ln & 0xC0:                     # EN: pointer — invalid here / FR: pointeur
                return None
            pos += 1
            labels.append(packet[pos:pos + ln].decode("ascii", "replace"))
            pos += ln
            if len(labels) > 32:
                return None
        return ".".join(labels).lower() or None
    except Exception:
        return None


def parse_qtype(packet: bytes) -> int:
    """EN: QTYPE of the first question (1=A, 28=AAAA, 65=HTTPS…). FR: idem."""
    try:
        pos = 12
        while pos < len(packet):
            ln = packet[pos]
            if ln == 0:
                return struct.unpack("!H", packet[pos + 1:pos + 3])[0]
            pos += 1 + ln
    except Exception:
        pass
    return 0


def build_nxdomain(query: bytes) -> bytes:
    """EN: NXDOMAIN response for a query: copy header+question, set QR,
    RCODE=3, zero answer counts. FR: réponse NXDOMAIN — copie
    en-tête+question, QR=1, RCODE=3, sections vides."""
    if len(query) < 12:
        return query
    flags = struct.unpack("!H", query[2:4])[0]
    flags |= 0x8000                          # QR: response
    flags = (flags & ~0x000F) | 0x0003       # RCODE = NXDOMAIN
    hdr = query[:2] + struct.pack("!H", flags) + query[4:6] + b"\x00\x00\x00\x00\x00\x00"
    # EN: question section ends after QNAME + QTYPE + QCLASS
    pos = 12
    while pos < len(query) and query[pos] != 0:
        pos += 1 + query[pos]
    end = min(pos + 5, len(query))           # null byte + qtype(2) + qclass(2)
    return hdr + query[12:end]


# ── Domain filter / Filtre de domaines ──────────────────────────────────────

class DomainFilter:
    """EN: Suffix-aware blocked-domain matcher. A list entry for
    `example.com` blocks `example.com` and any `*.example.com`. The
    whitelist wins over every list — it is the user's escape hatch.
    FR: Matcher suffixe. Une entrée `example.com` bloque `example.com` et
    tout `*.example.com`. La whitelist prime toujours."""

    def __init__(self) -> None:
        self._blocked: dict[str, str] = {}   # EN: domain -> category / FR: domaine -> catégorie
        self._whitelist: set[str] = set()

    def add(self, domain: str, category: str) -> None:
        domain = domain.strip().lower().rstrip(".")
        if domain and len(self._blocked) < _MAX_DOMAINS:
            self._blocked[domain] = category

    def clear_category(self, category: str) -> None:
        self._blocked = {d: c for d, c in self._blocked.items() if c != category}

    def whitelist_add(self, domain: str) -> None:
        self._whitelist.add(domain.strip().lower().rstrip("."))

    def whitelist_remove(self, domain: str) -> None:
        self._whitelist.discard(domain.strip().lower().rstrip("."))

    @staticmethod
    def _matches(domain: str, entry: str) -> bool:
        return domain == entry or domain.endswith("." + entry)

    def verdict(self, domain: str) -> str | None:
        """EN: category name if blocked, None if allowed. FR: catégorie si
        bloqué, None sinon."""
        domain = domain.lower().rstrip(".")
        for w in self._whitelist:
            if self._matches(domain, w):
                return None
        # EN: walk up the labels — longest match wins naturally since any
        #     suffix hit blocks. / FR: remonter les labels — tout suffixe
        #     présent bloque.
        parts = domain.split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            cat = self._blocked.get(suffix)
            if cat:
                return cat
        return None

    @property
    def size(self) -> int:
        return len(self._blocked)


# ── List fetching / Récupération des listes ─────────────────────────────────

def _parse_hosts(text: str, fmt: str = "hosts") -> list[str]:
    """EN: Extract domains from hosts-file format (`0.0.0.0 domain`) or
    plain one-per-line domain lists / URL lists. FR: extraction de
    domaines depuis format hosts ou listes simples/URLs."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "hosts":
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
                for d in parts[1:]:
                    if d not in ("localhost", "localhost.localdomain", "broadcasthost"):
                        out.append(d.split("#")[0])
                        break
        else:
            # EN: bare domain or URL (phishing feeds) / FR: domaine nu ou URL
            d = re.sub(r"^https?://", "", line).split("/")[0].split("#")[0].strip()
            if re.fullmatch(r"[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}", d, re.IGNORECASE):
                out.append(d)
    return out


def fetch_list(url: str, fmt: str = "hosts") -> tuple[list[str], str]:
    """EN: One bounded opt-in fetch. Returns (domains, report). Honest
    about failures — the caller surfaces them verbatim.
    FR: Un fetch borné opt-in. Retourne (domaines, rapport)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wiretap-DNSFW/1.0"})
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as r:
            raw = r.read(_MAX_LIST_BYTES + 1)
        if len(raw) > _MAX_LIST_BYTES:
            return [], f"list exceeds {_MAX_LIST_BYTES // 1024 // 1024} MiB cap — refused"
        text = raw.decode("utf-8", "replace")
        domains = _parse_hosts(text, fmt)
        return domains, f"fetched {len(domains)} domains ({len(raw) // 1024} KiB)"
    except Exception as e:                                   # noqa: BLE001 — report verbatim
        return [], f"fetch failed: {e}"


# ── The proxy server / Le serveur proxy ─────────────────────────────────────

class _DnsProtocol(asyncio.DatagramProtocol):
    """EN: asyncio UDP endpoint. Parses, filters, forwards, relays.
    FR: endpoint UDP asyncio. Parse, filtre, relaie."""

    def __init__(self, fw: DnsFirewall) -> None:
        self.fw = fw
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.ensure_future(self.fw.handle_query(data, addr, self.transport))

    def error_received(self, exc: Exception) -> None:        # EN: ICMP refused upstream etc.
        pass                                                 # FR: refus ICMP amont — ignoré


class DnsFirewall:
    """EN: Filtering DNS proxy lifecycle + state. Degrades honestly: if
    the bind fails (port taken, no privilege) `running` stays False and
    `last_error` says why. FR: cycle de vie + état du proxy filtrant.
    Dégrade honnêtement : bind impossible → running False + last_error."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.cache_dir = self.data_dir / "dnsfw_lists"
        self.filter = DomainFilter()
        self.enabled_categories: set[str] = set()
        self.upstream_mode = "system"        # EN: system | cloudflare | quad9 | google | doh_custom / FR: idem
        self.upstream_custom: str = ""
        self.bind_host = "127.0.0.1"
        self.bind_port = 5353
        self.running = False
        self.last_error = ""
        self.stats = {"queries": 0, "blocked": 0, "forwarded": 0,
                      "errors": 0, "started_at": None}
        self.per_category: dict[str, int] = {}
        self.recent_blocked: list[dict] = []
        self._transport: asyncio.DatagramTransport | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._upstream_udp: tuple[str, int] | None = None
        self._lock = threading.Lock()

    # ── configuration / configuration ───────────────────────────────────────

    def configure(self, *, categories: list[str] | None = None,
                  upstream_mode: str | None = None, upstream_custom: str | None = None,
                  bind_port: int | None = None) -> dict:
        """EN: Apply settings (persisted by the caller). Invalid keys are
        dropped silently — the status endpoint reports what stuck.
        FR: Applique les réglages — le endpoint de statut rapporte ce qui tient."""
        if categories is not None:
            self.enabled_categories = {c for c in categories if c in LIST_PRESETS}
        if upstream_mode in ("system", *DOH_PRESETS.keys(), "doh_custom"):
            self.upstream_mode = upstream_mode
        if upstream_custom is not None and upstream_custom.startswith("https://"):
            self.upstream_custom = upstream_custom
        if bind_port is not None and 1024 <= bind_port <= 65535 or bind_port == 53:
            self.bind_port = bind_port  # type: ignore[assignment]
        return self.status()

    def status(self) -> dict:
        return {
            "running": self.running,
            "bind": f"{self.bind_host}:{self.bind_port}",
            "upstream_mode": self.upstream_mode,
            "upstream": self._upstream_desc(),
            "categories": sorted(self.enabled_categories),
            "available_categories": {k: v["label"] for k, v in LIST_PRESETS.items()},
            "domains_loaded": self.filter.size,
            "last_error": self.last_error,
            "stats": self.stats,
            "per_category": self.per_category,
        }

    def _upstream_desc(self) -> str:
        if self.upstream_mode == "system":
            return f"system resolver ({(self._system_nameservers() or ['?'])[0]})"
        if self.upstream_mode == "doh_custom":
            return self.upstream_custom or "doh_custom (unset)"
        return f"DoH {self.upstream_mode}"

    # ── list management / gestion des listes ────────────────────────────────

    def refresh_lists(self, force: bool = False) -> dict:
        """EN: Fetch enabled categories that are missing or stale (>1 day),
        rebuild the matcher. Whitelist entries survive every refresh.
        FR: Fetch les catégories activées absentes ou périmées, reconstruit
        le matcher. La whitelist survit à tout refresh."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        report: dict[str, str] = {}
        new_filter = DomainFilter()
        new_filter._whitelist = set(self.filter._whitelist)
        for cat in sorted(self.enabled_categories):
            cache = self.cache_dir / f"{cat}.txt"
            domains: list[str] = []
            if cache.exists() and not force and (time.time() - cache.stat().st_mtime) < _REFRESH_INTERVAL:
                try:
                    domains = _parse_hosts(cache.read_text(errors="replace"),
                                           LIST_PRESETS[cat].get("format", "hosts"))
                    report[cat] = f"cache ({len(domains)} domains)"
                except Exception as e:                       # noqa: BLE001
                    report[cat] = f"cache unreadable: {e}"
            if not domains:
                domains, msg = fetch_list(LIST_PRESETS[cat]["url"],
                                          LIST_PRESETS[cat].get("format", "hosts"))
                if domains:
                    try:
                        cache.write_text("\n".join(domains))
                    except OSError:
                        pass
                report[cat] = msg
            for d in domains:
                new_filter.add(d, cat)
        # EN: carry over manual/ip entries? — rules in the firewall already
        #     handle IPs. DNS layer is domains only.
        with self._lock:
            self.filter = new_filter
        return {"report": report, "domains_loaded": self.filter.size}

    # ── upstream plumbing / plomberie amont ─────────────────────────────────

    @staticmethod
    def _system_nameservers() -> list[str]:
        servers: list[str] = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        try:
                            ipaddress.ip_address(parts[1])
                            servers.append(parts[1])
                        except ValueError:
                            pass
        except OSError:
            pass
        if not servers and os.name == "nt":                  # EN: Windows — psutil fallback
            try:                                             # FR: repli psutil
                import psutil
                for addrs in psutil.net_if_addrs().values():
                    for a in addrs:
                        pass                                 # FR: pas de DNS dans psutil — défaut
            except Exception:
                pass
        return servers or ["1.1.1.1"]

    async def _forward_udp(self, query: bytes) -> bytes | None:
        """EN: Stateless upstream UDP forward with 4s timeout, one retry.
        FR: Relais UDP amont sans état, timeout 4 s, un retry."""
        ns = self._system_nameservers()[0]
        loop = asyncio.get_running_loop()
        for attempt in range(2):
            try:
                return await asyncio.wait_for(self._udp_roundtrip(loop, query, ns), timeout=4.0)
            except (TimeoutError, OSError):
                continue
        return None

    @staticmethod
    async def _udp_roundtrip(loop, query: bytes, server: str) -> bytes:
        fut: asyncio.Future = loop.create_future()

        class Up(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)
            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: Up(), remote_addr=(server, _DNS_PORT))
        try:
            transport.sendto(query)
            return await fut
        finally:
            transport.close()

    async def _forward_doh(self, query: bytes) -> bytes | None:
        """EN: DoH wireformat POST (RFC 8484) via stdlib urllib in an
        executor — no external HTTP dep. FR: POST wireformat DoH (RFC 8484)
        via urllib stdlib dans un executor — aucune dep HTTP externe."""
        if self.upstream_mode == "doh_custom":
            url = self.upstream_custom
        else:
            url = DOH_PRESETS.get(self.upstream_mode, "")
        if not url:
            return None

        def _post() -> bytes | None:
            try:
                req = urllib.request.Request(
                    url, data=query,
                    headers={"Content-Type": "application/dns-message",
                             "Accept": "application/dns-message",
                             "User-Agent": "Wiretap-DNSFW/1.0"})
                with urllib.request.urlopen(req, timeout=6.0) as r:
                    return r.read(65535)
            except Exception as e:                           # noqa: BLE001
                logger.debug("DoH upstream failed: %s", e)
                return None

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _post)

    # ── query path / chemin de requête ──────────────────────────────────────

    async def handle_query(self, data: bytes, addr, transport) -> None:
        """EN: One query in, one answer out. Never raises into the
        datagram loop. / FR: Une requête entrée, une réponse sortie. Ne
        lève jamais dans la boucle datagram."""
        try:
            with self._lock:
                self.stats["queries"] += 1
            qname = parse_qname(data)
            category = self.filter.verdict(qname) if qname else None
            if category:
                with self._lock:
                    self.stats["blocked"] += 1
                    self.per_category[category] = self.per_category.get(category, 0) + 1
                    self.recent_blocked.append({
                        "ts": time.time(), "domain": qname, "category": category,
                        "qtype": parse_qtype(data), "client": addr[0] if addr else "?"})
                    if len(self.recent_blocked) > _MAX_BLOCKED_LOG:
                        del self.recent_blocked[:len(self.recent_blocked) - _MAX_BLOCKED_LOG]
                if transport:
                    transport.sendto(build_nxdomain(data), addr)
                return
            if self.upstream_mode == "system":
                answer = await self._forward_udp(data)
            else:
                answer = await self._forward_doh(data)
            if answer:
                with self._lock:
                    self.stats["forwarded"] += 1
                if transport:
                    transport.sendto(answer, addr)
            else:
                with self._lock:
                    self.stats["errors"] += 1
        except Exception as e:                               # noqa: BLE001 — UDP loop must not die
            logger.debug("handle_query error: %s", e)
            with self._lock:
                self.stats["errors"] += 1

    # ── lifecycle / cycle de vie ────────────────────────────────────────────

    async def start(self) -> dict:
        """EN: Bind and serve. Honest failure reporting — a busy port or
        missing privilege is a status, not a crash. FR: Bind et service.
        Échec honnête : port pris ou privilège manquant = statut, pas crash."""
        if self.running:
            return self.status()
        try:
            loop = asyncio.get_running_loop()
            self._loop = loop
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DnsProtocol(self),
                local_addr=(self.bind_host, self.bind_port),
                reuse_port=True)
            self._transport = transport  # type: ignore[assignment]
            self.running = True
            self.last_error = ""
            self.stats["started_at"] = time.time()
            logger.info("DNS firewall listening on %s:%s", self.bind_host, self.bind_port)
        except (OSError, PermissionError) as e:
            self.running = False
            hint = (" — bind :53 needs admin/root" if self.bind_port < 1024
                    else " — port already in use?")
            self.last_error = f"{e}{hint}"
            logger.warning("DNS firewall bind failed: %s", self.last_error)
        return self.status()

    async def stop(self) -> dict:
        if self._transport:
            self._transport.close()
            self._transport = None
        self.running = False
        return self.status()
