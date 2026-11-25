# Deep signals / Signaux profonds

[English](deep-signals.md) | [Français](deep-signals.md) | Español *(soon)* | Deutsch *(soon)* | Русский *(soon)* | 日本語 *(soon)* | Português *(soon)* | 中文 *(soon)*

## English

The deep signals are Wiretap's v1.8/v1.9 detection layer — the questions
no other firewall asks. Everything here is **local-first**: no cloud, no
telemetry, every verdict computed on your machine and explainable in one
sentence.

### Presence-correlated exfiltration — `UNATTENDED_EXFIL`

5 MB to an AI provider while you type is you using your IDE. The same
5 MB while you're away is something else acting in your name.

- **Sensor**: OS input-idle time — `IOHIDSystem` (macOS), `GetLastInputInfo`
  (Windows), `xprintidle` (X11 Linux). Zero privileges, zero keylogging —
  a single idle-second counter, never input content.
- **Logic**: sensitive outbound flow (AI provider, new rare destination,
  mass upload) × machine unattended beyond threshold → critical alert.
- **Honesty framing**: presence is *evidence, not verdict* — backups and
  cloud sync also upload while you're away. The alert says so and asks
  for confirmation. Linux/Wayland degrades honestly (no idle source).
- Cooldown-per-process logic fixed in v1.9 (latent dedup bug).

### Flow DNA — `FLOW_DRIFT`

A compromised app keeps its name but changes its metabolism.

- **Profile per process**: burst sizes, inter-flow rhythm (coefficient of
  variation), out:in byte ratio, destination entropy — browsers disperse,
  exfiltration tunnels.
- **Learning**: 30 flows silently, then non-overlapping scoring windows —
  a slow drift cannot dilute itself across overlapping windows.
- **Multi-feature requirement**: 2+ independent features past threshold.
  Watching a video changes one feature; being compromised changes them
  all — structural false-positive resistance.
- **Explainable**: "rhythm collapsed 4.2x, out:in inverted, destinations
  tunneled (entropy 3.3 → 0 bits)" — plus one-click re-baseline.
- Endpoints: `GET /flowdna`, `POST /flowdna/rebaseline`, `POST /flowdna/dismiss`.

### Process-lineage verdicts — `LINEAGE_SUSPECT`

`browser -> sh -> curl -> evil.bin` tells the story a bare process name
hides. Ancestry scoring: shells/interpreters in the chain, browser/Office/
terminal roots, nesting depth — rendered as a plain evidence sentence.
Cross-platform: `/proc` + psutil on Linux/macOS, PowerShell CIM process
table on Windows (wmic removed from Windows 11 — never relied on).

### Persistence surface watch — `PERSISTENCE_NEW/MOD/DEL`

What malware needs most is surviving reboot — and every network-first
tool misses it.

- Enumerates without privileges: LaunchAgents/Daemons (macOS), Run keys +
  startup folder (Windows), systemd units, cron, autostart (Linux).
- Fingerprints each entry (target path + binary hash + content hash),
  diffs every 5 minutes — deletion is itself a signal (post-infection
  cleanup).
- Risk scoring: `/tmp` targets (+3 — legitimate software doesn't
  auto-start from temp), interpreter-as-target (+2 — real payload hidden
  in script argument), run-at-load + keep-alive.
- Endpoint: `GET /persistence`. Windows scope: Run keys (services and
  scheduled tasks on the frontier list).

### Blast radius — automated impact assessment

Every critical alert carries a computed answer to "if this was malicious,
what did it touch":

- network footprint per destination (procdest SQLite join), AI-provider
  exposure, secret shapes in reach, survives-reboot check, lineage,
  open files.
- Every field labeled with **source + confidence**; failures degrade to
  "unknown", never to silence.
- Attached as `blast_worst_case` on the alert itself; shown in the UI.
- Endpoints: `GET /impact/process/{name}`, `GET /impact/alert/{id}`.
- Honest degradation: open-files section is "unknown" on Windows
  (no `/proc`, no lsof) — documented, not hidden.

### Time-travel state diff

"What changed on this machine since Tuesday?" — the first question of
every investigation, answered in milliseconds.

- Hourly snapshots: persistence entries, listening ports with owners,
  process shapes. Disk-persisted, 48 h retention.
- Diff any point: appeared / vanished / mutated, risk-noted.
- Endpoints: `GET /timetravel/status`, `POST /timetravel/snapshot`,
  `GET /timetravel/diff?since=<ts>`.
- Linux without lsof: `/proc/net/tcp` hex parser — zero dependencies.

### Tamper-evident forensic log

Every alert is hash-chained to the previous one (transparency-log
construction): `hash[n] = sha256(hash[n-1] | alert[n])`.

- An attacker wiping or editing past alerts **breaks the chain** —
  deletion itself becomes evidence.
- Continuity across restarts; chain head pinnable externally for
  mathematical finality.
- Offline verification: `GET /forensic/verify`.

### Kill-chain correlation

Three distinct detector families on the same entity within 15 minutes is
not noise — it's one incident.

- 15-minute sliding window per entity (process preferred, IP fallback);
  families: network, presence, metabolism, lineage, persistence, supply
  chain, secrets, AI governance…
- Same-detector repetitions never count as a chain — amplification of
  false positives is structurally impossible.
- Wired *before* the auto-responder: a correlated chain can itself
  trigger lockdown — one narrated incident instead of three separate
  noises.

### MCP governance — the AI-agent attack surface

Risk audit of every MCP server declared in Cursor, Claude (Desktop +
Code including per-project nesting), Windsurf, Zed, VS Code and
Devin CLI configs.

- Scores download-and-run launchers (`npx`/`uvx` — package fetched at
  runtime, nothing pinned auditable), unscoped filesystem access,
  shell/browser capabilities, secrets passed in env (shape-only —
  values never leave).
- Endpoint: `GET /mcp/audit`; risky servers surface in Settings →
  Deep signals.

### Cross-platform honesty matrix

| Signal | macOS | Windows | Linux |
|---|---|---|---|
| Presence | IOHID | GetLastInputInfo | xprintidle (X11; Wayland degrades) |
| Flow DNA / killchain / forensic chain | full | full | full (pure Python) |
| Lineage | psutil | PowerShell CIM (simulated-tested) | /proc + psutil |
| Persistence | LaunchAgents/Daemons | Run keys | systemd/cron/autostart |
| Time-travel listeners | lsof | PowerShell structured netstat | lsof or /proc/net/tcp |
| Blast open-files | lsof | unknown (honest) | /proc |

Windows sensors use **PowerShell structured output** — immune to
localized `netstat` ("ABHÖREN", "ÉCOUTE"…) — with positional-parsing
fallback. Verified by German-locale fixture tests and green CI on
`windows-latest`.

---

## Français

Les signaux profonds sont la couche de détection v1.8/v1.9 de Wiretap —
les questions qu'aucun autre pare-feu ne pose. Tout est **local-first** :
pas de cloud, pas de télémétrie, chaque verdict calculé sur votre machine
et explicable en une phrase.

### Exfiltration corrélée à la présence — `UNATTENDED_EXFIL`

5 Mo vers un provider IA pendant que vous tapez, c'est vous avec votre
IDE. Les mêmes 5 Mo pendant votre absence, c'est autre chose qui agit en
votre nom.

- **Capteur** : temps d'inactivité de l'input OS — `IOHIDSystem` (macOS),
  `GetLastInputInfo` (Windows), `xprintidle` (X11 Linux). Zéro privilège,
  zéro keylogging — un simple compteur de secondes d'inactivité, jamais
  le contenu des saisies.
- **Logique** : flux sortant sensible (provider IA, destination rare
  nouvelle, upload massif) × machine inactive au-delà du seuil → alerte
  critique.
- **Honnêteté** : la présence est une *preuve, pas un verdict* — les
  backups et syncs cloud uploadent aussi en votre absence. L'alerte le
  dit et demande confirmation. Linux/Wayland dégrade honnêtement.

### Flow DNA — `FLOW_DRIFT`

Une app compromise garde son nom mais change de métabolisme : tailles de
rafales, rythme inter-flux, ratio sortant:entrant, entropie des
destinations. Apprentissage silencieux (30 flux), fenêtres de scoring non
recouvrantes, exigence multi-feature (2+) contre les faux positifs, alertes
explicables, re-baseline en un clic. Endpoints `/flowdna`.

### Verdicts par lignée — `LINEAGE_SUSPECT`

`navigateur -> sh -> curl -> evil.bin` raconte l'histoire qu'un nom de
processus cache. Scoring d'ascendance avec phrase de preuve. Windows :
table processus PowerShell CIM (wmic supprimé de Windows 11).

### Surveillance de persistance — `PERSISTENCE_NEW/MOD/DEL`

Survivre au reboot est ce dont le malware a le plus besoin — et tous les
outils network-first le ratent. LaunchAgents/Daemons, clés Run, systemd,
cron, autostart — empreintes comparées toutes les 5 minutes ; la
suppression elle-même est un signal. Endpoint `GET /persistence`.

### Rayon de blast — évaluation d'impact automatisée

Chaque alerte critique porte la réponse calculée à « si c'était malveillant,
qu'est-ce que ça a touché » : destinations, exposition IA, secrets à
portée, survie au reboot, lignée, fichiers ouverts — chaque champ labellé
source + confiance, dégradation honnête vers « unknown ». Attaché comme
`blast_worst_case`, visible dans l'UI.

### Diff temporel

« Qu'est-ce qui a changé sur cette machine depuis mardi ? » — snapshots
horaires (persistance + listeners + formes de processus), rétention 48 h,
diff appeared/vanished/mutated en millisecondes. Linux sans lsof : parseur
`/proc/net/tcp` zéro dépendance.

### Journal forensique inviolable

Chaque alerte hash-chainée à la précédente : un attaquant qui efface des
alertes **casse la chaîne** — la suppression devient la preuve. Continuité
entre redémarrages, vérification offline sur `GET /forensic/verify`.

### Corrélation kill-chain

3 familles de détecteurs distinctes sur la même entité en 15 minutes, ce
n'est pas du bruit — c'est un incident unique. Les répétitions du même
détecteur ne comptent jamais ; branché avant l'auto-responder : une chaîne
corrélée peut déclencher le lockdown.

### Gouvernance MCP — la surface d'attaque des agents IA

Audit de risque de chaque serveur MCP déclaré dans Cursor, Claude (Desktop
+ Code, imbrication par projet incluse), Windsurf, Zed, VS Code et Devin
CLI : lanceurs download-and-run, accès filesystem non scopé, capacités
shell/browser, secrets en env (formes salées uniquement). Endpoint
`GET /mcp/audit`.

### Matrice d'honnêteté cross-plateforme

| Signal | macOS | Windows | Linux |
|---|---|---|---|
| Présence | IOHID | GetLastInputInfo | xprintidle (X11 ; Wayland dégrade) |
| Flow DNA / killchain / chaîne | complet | complet | complet (pur Python) |
| Lignée | psutil | PowerShell CIM | /proc + psutil |
| Persistance | LaunchAgents/Daemons | clés Run | systemd/cron/autostart |
| Listeners time-travel | lsof | netstat PowerShell structuré | lsof ou /proc/net/tcp |
| Fichiers ouverts blast | lsof | unknown (honnête) | /proc |

Les capteurs Windows utilisent la **sortie structurée PowerShell** —
immunisés contre le `netstat` localisé — avec fallback positionnel.
Vérifié par fixtures de locale allemande et CI verte sur
`windows-latest`.
