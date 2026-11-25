"""
EN: Automatic response — detection without reaction is a surveillance
    camera filming a burglary. When a CRITICAL alert of a configured type
    fires, Wiretap can act immediately:

      * `lockdown` — engage the firewall lockdown (all non-whitelisted
        egress blocked): ransomware encrypting files can't reach its C2,
        the postinstall dropper can't fetch stage two, the secret thief
        can't exfiltrate;
      * `suspend` — SIGSTOP/taskkill-suspend the offending process when
        the alert carries a pid.

    Everything is OPT-IN per action (default: notify only), every action
    is logged as its own alert, and lockdown auto-engagement can be
    scoped to specific alert types. No silent magic: the UI shows what
    fired and what Wiretap did about it.

FR: Réponse automatique — détecter sans réagir, c'est une caméra qui
    filme un cambriolage. Quand une alerte CRITICAL d'un type configuré
    tire, Wiretap peut agir : lockdown pare-feu (l'égress non whitelisté
    coupé — le ransomware ne joint plus son C2) et/ou suspension du
    processus fautif. Tout est OPT-IN, chaque action est journalisée
    comme alerte, aucune magie silencieuse.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time

logger = logging.getLogger("wiretap.autorespond")

# EN: Alert types eligible for auto-response — the ones where seconds
#     matter. User-configurable subset. / FR: types éligibles — ceux où
#     les secondes comptent.
ELIGIBLE_TYPES = {
    "RANSOMWARE_CANARY", "POSTINSTALL_NET", "SECRET_PLAINTEXT_LEAK",
    "HONEYPORT_TOUCH", "C2_BEACON", "AI_UPLOAD_SPIKE", "KILLCHAIN",
}


class AutoResponder:
    """EN: Rule engine — observe(alert_dict) called from the alert pipeline,
    actions executed at most once per cooldown. / FR: moteur de règles —
    observe() appelé depuis le pipeline, actions bornées par cooldown."""

    def __init__(self, fw=None) -> None:  # noqa: ANN001
        self.fw = fw
        self.enabled = False                    # EN: master opt-in / FR: opt-in maître
        self.actions: dict[str, list[str]] = {} # EN: alert_type -> ["lockdown","suspend"] / FR: type -> actions
        self.cooldown_s = 300.0
        self._last_action: dict[str, float] = {}
        self._log: list[dict] = []
        self._lock = threading.Lock()

    def configure(self, *, enabled: bool | None = None,
                  actions: dict | None = None) -> dict:
        with self._lock:
            if enabled is not None:
                self.enabled = bool(enabled)
            if actions is not None:
                valid = {"lockdown", "suspend"}
                self.actions = {
                    str(k): [a for a in v if a in valid]
                    for k, v in actions.items()
                    if k in ELIGIBLE_TYPES and isinstance(v, list)
                }
        return self.status()

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "actions": dict(self.actions),
                "eligible_types": sorted(ELIGIBLE_TYPES),
                "recent": list(self._log[-20:]),
            }

    def observe(self, alert_type: str, severity: str,
                pid: int | None = None) -> list[dict]:
        """EN: React to an alert. Returns action records (also appended to
        the audit log). / FR: réagir à une alerte. Renvoie les actions."""
        if not self.enabled or severity != "critical":
            return []
        with self._lock:
            acts = list(self.actions.get(alert_type, []))
        if not acts:
            return []
        now = time.time()
        records = []
        for act in acts:
            key = f"{alert_type}:{act}"
            with self._lock:
                if now - self._last_action.get(key, 0) < self.cooldown_s:
                    continue
                self._last_action[key] = now
            rec = {"action": act, "alert_type": alert_type, "ts": now,
                   "ok": False, "detail": ""}
            if act == "lockdown":
                rec["ok"], rec["detail"] = self._do_lockdown()
            elif act == "suspend" and pid:
                rec["ok"], rec["detail"] = self._do_suspend(pid)
            elif act == "suspend":
                rec["detail"] = "no pid in alert"
            records.append(rec)
            with self._lock:
                self._log.append(rec)
        return records

    def _do_lockdown(self) -> tuple[bool, str]:
        if self.fw is None:
            return False, "no firewall orchestrator"
        try:
            self.fw.lockdown = True
            return True, "firewall lockdown engaged"
        except Exception as e:                      # noqa: BLE001
            return False, str(e)

    @staticmethod
    def _do_suspend(pid: int) -> tuple[bool, str]:
        try:
            if os.name == "posix":
                os.kill(pid, signal.SIGSTOP)
                return True, f"process {pid} suspended (SIGSTOP)"
            return False, "suspend unsupported on this platform"
        except (OSError, ProcessLookupError) as e:
            return False, str(e)
