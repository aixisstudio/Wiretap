# Hoja de ruta

[English](ROADMAP.md) | [Français](ROADMAP.md) | **Español** | [Deutsch](ROADMAP.de.md) | [Русский](ROADMAP.ru.md) | [日本語](ROADMAP.ja.md) | [Português](ROADMAP.pt-BR.md) | [中文](ROADMAP.zh-CN.md)

> Sugiere o vota funciones en [GitHub Discussions](https://github.com/aixisstudio/Wiretap/discussions) — categoría *Ideas*. Para bugs concretos, usa [Issues](https://github.com/aixisstudio/Wiretap/issues).

## ✅ Entregado

| Versión | Qué llegó |
|---|---|
| **v1.0.4** | Primera release pública — grafo en tiempo real + mapa mundial, atribución por proceso, geolocalización offline (.mmdb), alertas de anomalías, privacy score, descubrimiento LAN pasivo (ARP/OUI), monitoreo micro/cámara (Windows/Linux), modo demo, UI EN/FR |
| **v1.0.5** | **Soporte Windows** (Npcap, backend empaquetado), iconos de proceso, +24 dominios tracker, correcciones |
| **v1.2 (main, sin tag)** | **Suite de seguridad y caza de amenazas** — orquestación del firewall del SO (reglas IP/CIDR/dominio/proceso/puerto vía `netsh`/`iptables`/`pf`, best-effort), botón lockdown, acciones kill/suspend, threat intel opt-in (AbuseIPDB/OTX/VirusTotal), webhooks opt-in (Discord/Slack/Telegram/genérico), detección de túnel DNS / tráfico en claro / desviación de país, auditoría de seguridad, export forense (árbol de procesos + SHA-256, JSON/CSV/STIX), UI en 8 idiomas |
| **v1.5.x** | **Capa enterprise/SOC** — `wiretap.toml` declarativo, syslog CEF + RFC 3164 + `format=ecs` NDJSON, importación Sigma + exportación YARA-L, vista `/remote/fleet` + chart Helm, despliegues Ansible/Puppet/Salt/GPO, unidad systemd endurecida + nfpm `.deb`/`.rpm`, feeds TI gratuitos, MkDocs + `INTEGRATIONS.md` en 7 idiomas |
| **v1.6.x** | **Agente e identidad de flota** — agente Rust sin dependencias (`agent/`, atribución `/proc` socket→PID en Linux), enrollment por agente (tokens `sagt_…` hasheados, `/ingest/revoke`), worker de actualización `ti_feeds` automático, CI del agente en 3 SO, fórmula headless `wiretapd`, todas las alertas CodeQL cerradas, 235 tests backend |

También en marcha: imagen Docker en GHCR, tap de Homebrew (`brew install --cask aixisstudio/tap/wiretap` + fórmula headless `wiretapd`), paquete winget [enviado](https://github.com/microsoft/winget-pkgs/pull/455520), README en 8 idiomas, GitHub Discussions.

| **v1.8.0** | **Las señales profundas** — exfiltración correlacionada con presencia (`UNATTENDED_EXFIL`), registro forense encadenado por hash (`/forensic/verify`), veredictos por linaje, correlación kill-chain (3 familias de detectores / 15 min = un incidente), DNS de sistema en un clic, gobernanza del trafico IA (21 proveedores, shadow-AI), DLP local de secretos, vigilancia supply-chain (`POSTINSTALL_NET`), consultas `/ask` en lenguaje natural, canarios anti-ransomware, honeyports LAN, respuesta automática opt-in, firewall DNS con upstream DoH, perfiles por red Wi-Fi, digest de privacidad compartible |
| **v1.9.0** | **Flow DNA + ciclo de intrusión cerrado** — metabolismo de red por proceso (`FLOW_DRIFT` explicable), auditoría de gobernanza MCP (Cursor/Claude/Windsurf/Zed/VS Code/Devin), vigilancia de persistencia (`PERSISTENCE_NEW/MOD/DEL`), radio de impacto en cada alerta critica, diff temporal (snapshots horarios, 48 h), endurecimiento cross-plataforma (sensores Windows inmunes al `netstat` localizado, fallback `/proc/net/tcp` en Linux), 423 tests verdes en los 3 SO |

## 🚧 v1.x — en curso

- [x] **Instalador Windows firmado** — CI conectada a [SignPath](https://signpath.org) OSS (Authenticode gratuito para proyectos aprobados); se activa al aceptar la solicitud — ver `docs/SIGNING.md`
- [ ] **Build macOS firmado y notarizado** — requiere cuenta Apple Developer (99 $/año), no hay vía gratuita. Mientras tanto, el [tap](https://github.com/aixisstudio/homebrew-tap) quita la cuarentena
- [ ] **Homebrew upstream** (`brew install --cask wiretap`) — bloqueado: el nombre `wiretap` ya lo usa otro proyecto; se retomará con la firma Developer ID
- [ ] **Publicación winget** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) (v1.0.8) abierta; el pipeline enviará builds NSIS nuevos en cada tag
- [ ] **Chocolatey** — paquete listo; espera el secreto `CHOCO_API_KEY`
- [ ] **Atribución del agente en Windows/macOS** — backends `GetExtendedTcpTable`/`libproc`
- [ ] **Escala de flota** — colector con cola + PostgreSQL/TimescaleDB para >1 000 agentes
- [x] **Instaladores Windows de 1 clic** — NSIS Electron + Inno Lite, en CI por tag; desde v1.0.6
- [x] **Paquetes Linux** — .deb / AppImage / **snap** además de Docker (sin Flatpak: la sandbox no puede exponer la captura)
- [x] **Auto-actualización** — electron-updater sobre los feeds `latest-*.yml`, desactivable en Ajustes
- [x] **Formatos de export** — grafo + alertas a JSON/CSV en la UI
- [ ] **Más cobertura de trackers** — listas editables por la comunidad en `backend/classifier/lists/`
- [ ] **Export PCAP** — por host o sesión

## 💭 En estudio

- Reglas de alerta personalizadas en la UI
- Emparejamiento remoto opcional para hosts sin pantalla — con consentimiento y token
- Capas del mapa: vista ASN / organización
- Importación de blocklists (StevenBlack hosts, EasyList) — requiere revisión de privacidad/licencias
- Perfiles de firewall (estricto/viaje vs desarrollador/permisivo)

## 🔬 Investigación — documentado, no implementado

Ideas que llevarían a Wiretap hacia un EDR/XDR de escritorio. Se listan con
honestidad — **ninguna está implementada**; cada una exige diseño propio,
componentes nativos y a menudo un segundo artefacto binario:

- **Sondas eBPF (Linux)** — captura kernel-space de `sys_enter_connect`/`accept`, resistente a evasión; requiere programa BPF compilado + root
- **Callout WFP (Windows)** — filtrado real en kernel en lugar de orquestar `netsh`; requiere driver firmado
- **NetworkExtension (macOS)** — `NEFilterProvider` para filtrar por bundle; requiere Apple Developer ID + entitlements
- **Correlación memoria/flujo** — inspección de DLL sin firmar / regiones `PAGE_EXECUTE_READWRITE` cruzada con conexiones sospechosas
- **Dynamic Taint Analysis** — probar la exfiltración byte a byte; investigación pesada
- **SLM SecOps local** — modelo de 1–3 B parámetros que explique alertas en lenguaje natural
- **Intel de flota con ZKP** — compartir detecciones entre pares sin revelar endpoints
- **Contadores PMU/hardware** — indicios de ransomware bajo el SO (especulación, ráfagas de cifrado)
- **Integridad Merkle de módulos cargados** — detectar DLL parcheadas en caliente antes del primer paquete
- **Sinkholing / micro-contención** — redirigir un flujo sospechoso a un honeypot local en vez de matarlo
- **Export PCAP** sigue en el alcance de arriba

## 🚫 Fuera de alcance

Deliberadamente, por diseño:

- **Telemetría, analíticas, cuentas, sincronización cloud** — nunca.
- **IDS pasivo a escala de red** — Wiretap vigila *esta* máquina, no toda la red.
- **Filtrado de paquetes en user-space** — el bloqueo se delega al firewall nativo del SO (o a futuros componentes kernel), nunca se reimplementa.

## 🤝 Contribuir

Buenos puntos de entrada: etiquetas `good first issue`, PRs de listas de trackers (`backend/classifier/lists/`), traducciones (i18n lista, un archivo por idioma), empaquetado (Linux .deb/.rpm). Ver [CONTRIBUTING.md](CONTRIBUTING.md).
