"""
EN: Kill-chain correlator — the difference between a pile of detectors and
    a security system. One weak signal is noise; three DIFFERENT signals
    hitting the same entity inside a short window is an attack unfolding:

        postinstall execution  +  first AI contact  +  registry anomaly
        canary touched         +  lockdown-worthy network spike
        C2 beacon              +  high-entropy cleartext + ICMP tunnel

    Human analysts correlate these in their heads — or more often don't,
    because alerts arrive as disconnected noise. The correlator does it
    continuously: per entity (process or remote IP), a sliding window of
    DISTINCT signal types; when the diversity threshold is reached, one
    KILLCHAIN critical alert names the whole chain with its timeline.

    Deliberate design: it never invents severity — it REQUIRES multiple
    independent detector families to have fired, so false-positive
    amplification is structurally bounded. The entity key prefers process
    over IP because post-2015 malware lives in processes, not hosts.

FR: Corrélateur kill-chain — la différence entre un tas de détecteurs et
    un système de sécurité. Un signal faible est du bruit ; trois signaux
    DIFFÉRENTS frappant la même entité dans une courte fenêtre sont une
    attaque en train de se dérouler. Le corrélateur maintient par entité
    (processus ou IP) une fenêtre glissante de types de signaux distincts
    et émet une alerte KILLCHAIN critique nommant la chaîne entière avec
    sa timeline. Il n'invente jamais de sévérité : il EXIGE plusieurs
    familles de détecteurs indépendantes, donc l'amplification de faux
    positifs est structurellement bornée.
"""

from __future__ import annotations

import threading
import time

WINDOW_S = 900.0               # EN: 15 min correlation window / FR: fenêtre 15 min
DIVERSITY_THRESHOLD = 3        # EN: distinct signal families needed / FR: familles requises
COOLDOWN_S = 3600.0            # EN: one killchain alert per entity/hour / FR: une par entité/heure

# EN: Signal families — grouping prevents 3 miner alerts counting as a chain.
# FR: familles de signaux — évite que 3 alertes de minage comptent comme chaîne.
FAMILIES = {
    "supplychain": {"PKG_REGISTRY_ANOMALY", "POSTINSTALL_NET"},
    "ai":          {"SHADOW_AI", "AI_UPLOAD_SPIKE", "AI_SECRET_EXPOSURE"},
    "secrets":     {"SECRET_PLAINTEXT_LEAK"},
    "c2":          {"C2_BEACON", "DGA", "JA3_MALWARE", "ML_ANOMALY"},
    "exfil":       {"HIGH_ENTROPY", "ICMP_TUNNEL", "UPLOAD_SPIKE"},
    "ransomware":  {"RANSOMWARE_CANARY"},
    "lan":         {"HONEYPORT_TOUCH", "NEW_DEVICE"},
    "integrity":   {"INTEGRITY_HOLLOWING", "INTEGRITY_TAMPER", "HOLLOWING"},
    "presence":    {"UNATTENDED_EXFIL"},
    "lineage":     {"LINEAGE_SUSPECT"},
    "mining":      {"MINER_STRATUM", "MINER_CPU", "MINING"},
    "dns":         {"DNS_TUNNEL", "DNSFW_POLICY"},
}

TYPE_TO_FAMILY = {t: fam for fam, types in FAMILIES.items() for t in types}


class KillChain:
    """EN: Sliding-window correlator. Feed every alert via observe(); emits
    at most one composite alert per entity per cooldown.
    FR: corrélateur à fenêtre glissante. Alimenter chaque alerte via
    observe() ; émet au plus une alerte composite par entité/cooldown."""

    def __init__(self, window_s: float = WINDOW_S,
                 threshold: int = DIVERSITY_THRESHOLD) -> None:
        self.window_s = window_s
        self.threshold = threshold
        self._lock = threading.Lock()
        # EN: entity -> list of (ts, family, type, message)
        # FR: entité -> liste de (ts, famille, type, message)
        self._events: dict[str, list[tuple]] = {}
        self._alerted: dict[str, float] = {}
        self.enabled = True

    @staticmethod
    def entity_key(details: dict, node_id: str | None) -> str | None:
        proc = (details or {}).get("process")
        if proc:
            return f"proc:{str(proc).lower()}"
        if node_id:
            return f"ip:{node_id}"
        if (details or {}).get("remote_ip"):
            return f"ip:{details['remote_ip']}"
        if (details or {}).get("remote"):
            return f"ip:{details['remote']}"
        if (details or {}).get("hostname"):
            return f"host:{details['hostname']}"
        return None

    def observe(self, alert_type: str, severity: str,
                details: dict | None = None,
                node_id: str | None = None,
                message: str = "") -> dict | None:
        """EN: Feed one alert. Returns a composite KILLCHAIN alert dict when
        the entity crosses the diversity threshold, else None.
        FR: alimenter une alerte. Renvoie une alerte composite KILLCHAIN si
        l'entité franchit le seuil de diversité, sinon None."""
        if not self.enabled:
            return None
        family = TYPE_TO_FAMILY.get(alert_type)
        if not family:
            return None
        key = self.entity_key(details or {}, node_id)
        if not key:
            return None
        now = time.time()
        with self._lock:
            evts = self._events.setdefault(key, [])
            evts.append((now, family, alert_type, message[:120]))
            # EN: window GC / FR: nettoyage fenêtre
            cutoff = now - self.window_s
            self._events[key] = [e for e in evts if e[0] > cutoff]
            evts = self._events[key]

            families = sorted({e[1] for e in evts})
            if len(families) < self.threshold:
                return None
            if now - self._alerted.get(key, 0) < COOLDOWN_S:
                return None
            self._alerted[key] = now

            timeline = sorted(evts)
            chain = [{"ts": round(ts, 1), "family": fam, "type": typ,
                      "message": msg} for ts, fam, typ, msg in timeline]
            self._events[key] = []                  # EN: chain consumed / FR: chaîne consommée

        entity = key.split(":", 1)[1]
        fams = ", ".join(families)
        return {
            "type": "KILLCHAIN",
            "severity": "critical",
            "message": f"Correlated attack chain on {entity}: {len(families)} independent "
                       f"signal families ({fams}) inside {int(self.window_s // 60)} min — "
                       f"this is not noise, treat as an active incident",
            "details": {"entity": key, "families": families,
                        "chain": chain, "window_s": self.window_s},
        }

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "entities_tracked": len(self._events),
                "chains_fired": len(self._alerted),
                "threshold": self.threshold,
                "window_s": self.window_s,
            }
