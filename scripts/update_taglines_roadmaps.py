#!/usr/bin/env python3
"""Update taglines in translated READMEs + add v1.8/v1.9 rows to translated ROADMAPs."""
import io

TAGLINES = {
    "es": ("**Rastrea cada conexión oculta.**",
           "**El firewall que sabe si TU estabas ahi cuando los datos salieron.**"),
    "de": ("**Verfolge jeden versteckten Netzwerkfluss.**",
           "**Die Firewall, die weiss, ob DU da warst, als die Daten rausgingen.**"),
    "ru": ("**Отслеживай каждое скрытое соединение.**",
           "**Файрвол, который знает, были ли ВЫ рядом, когда данные ушли.**"),
    "ja": ("**隠れたネットワーク接続をすべて追跡。**",
           "**データが出ていった時、あなたがそこにいたかを知るファイアウォール。**"),
    "pt-BR": ("**Rastreie cada conexão escondida.**",
              "**O firewall que sabe se VOCE estava la quando os dados sairam.**"),
    "zh-CN": ("**追踪每一个隐藏的网络连接。**",
              "**知道数据离开时你是否在场的防火墙。**"),
}

ROADMAP_ROWS = {
    "es": """| **v1.8.0** | **Las senales profundas** — exfiltracion correlacionada con presencia (`UNATTENDED_EXFIL`), registro forense encadenado por hash (`/forensic/verify`), veredictos por linaje, correlacion kill-chain (3 familias de detectores / 15 min = un incidente), DNS de sistema en un clic, gobernanza del trafico IA (21 proveedores, shadow-AI), DLP local de secretos, vigilancia supply-chain (`POSTINSTALL_NET`), consultas `/ask` en lenguaje natural, canarios anti-ransomware, honeyports LAN, respuesta automatica opt-in, firewall DNS con upstream DoH, perfiles por red Wi-Fi, digest de privacidad compartible |
| **v1.9.0** | **Flow DNA + ciclo de intrusion cerrado** — metabolismo de red por proceso (`FLOW_DRIFT` explicable), auditoria de gobernanza MCP (Cursor/Claude/Windsurf/Zed/VS Code/Devin), vigilancia de persistencia (`PERSISTENCE_NEW/MOD/DEL`), radio de impacto en cada alerta critica, diff temporal (snapshots horarios, 48 h), endurecimiento cross-plataforma (sensores Windows inmunes al `netstat` localizado, fallback `/proc/net/tcp` en Linux), 423 tests verdes en los 3 SO |
""",
    "de": """| **v1.8.0** | **Die tiefen Signale** — anwesenheitskorrelierte Exfiltration (`UNATTENDED_EXFIL`), hash-verkettetes manipulationssicheres Forensik-Log (`/forensic/verify`), Herkunfts-Verdikte, Kill-Chain-Korrelation (3 Detektor-Familien / 15 Min = ein Vorfall), System-DNS per Klick, KI-Traffic-Governance (21 Anbieter, Shadow-AI), lokale Secret-DLP, Supply-Chain-Watch (`POSTINSTALL_NET`), `/ask`-Naturlichsprachenabfragen, Ransomware-Canaries, LAN-Honeyports, opt-in Auto-Response, DNS-Firewall mit DoH-Upstream, WLAN-basierte Profile, teilbarer Privacy-Digest |
| **v1.9.0** | **Flow DNA + geschlossener Intrusion-Zyklus** — Netzwerk-Metabolismus pro Prozess (`FLOW_DRIFT` erklarbar), MCP-Governance-Audit (Cursor/Claude/Windsurf/Zed/VS Code/Devin), Persistenz-Uberwachung (`PERSISTENCE_NEW/MOD/DEL`), Blast-Radius in jedem kritischen Alarm, Zeitreise-Diff (stundliche Snapshots, 48 h), Cross-Plattform-Hartung (Windows-Sensoren immun gegen lokalisiertes `netstat`, `/proc/net/tcp`-Fallback fur Linux), 423 Tests grun auf allen 3 OS |
""",
    "ru": """| **v1.8.0** | **Глубокие сигналы** — эксфильтрация с корреляцией присутствия (`UNATTENDED_EXFIL`), неподделываемый хеш-связанный форензик-журнал (`/forensic/verify`), вердикты по происхождению, корреляция kill-chain (3 семейства детекторов / 15 мин = один инцидент), системный DNS в один клик, управление AI-трафиком (21 провайдер, shadow-AI), локальный DLP секретов, наблюдение за supply-chain (`POSTINSTALL_NET`), запросы `/ask` на естественном языке, канарейки против ransomware, LAN-ханипорты, опциональный автоответ, DNS-файрвол с DoH-апстримом, профили по Wi-Fi сети, публичный дайджест приватности |
| **v1.9.0** | **Flow DNA + закрытый цикл вторжения** — сетевой метаболизм процессов (`FLOW_DRIFT` с объяснениями), аудит MCP-управления (Cursor/Claude/Windsurf/Zed/VS Code/Devin), наблюдение за персистентностью (`PERSISTENCE_NEW/MOD/DEL`), радиус поражения в каждом критическом алерте, разница во времени (ежечасные снапшоты, 48 ч), кроссплатформенное укрепление (сенсоры Windows, невосприимчивые к локализованному `netstat`, fallback `/proc/net/tcp` для Linux), 423 теста зелёные на всех 3 ОС |
""",
    "ja": """| **v1.8.0** | **ディープシグナル** — プレゼンス相関エクスフィルトレーション(`UNATTENDED_EXFIL`)、ハッシュチェーン改ざん検知フォレンジックログ(`/forensic/verify`)、系譜判定、キルチェーン相関(3検出器ファミリー/15分=1インシデント)、ワンクリックシステムDNS、AIトラフィックガバナンス(21プロバイダ、shadow-AI)、ローカルDLP、サプライチェーン監視(`POSTINSTALL_NET`)、自然言語`/ask`クエリ、ランサムウェアカナリア、LANハニーポート、opt-in自動対応、DoHアップストリーム付きDNSファイアウォール、Wi-Fiごとのプロファイル、共有可能なプライバシーダイジェスト |
| **v1.9.0** | **Flow DNA + 侵入サイクル閉環** — プロセスごとのネットワーク代謝(`FLOW_DRIFT`説明可能)、MCPガバナンス監査(Cursor/Claude/Windsurf/Zed/VS Code/Devin)、永続化監視(`PERSISTENCE_NEW/MOD/DEL`)、全クリティカルアラートにブラスト半径、タイムトラベル差分(毎時スナップショット、48時間)、クロスプラットフォーム強化(ローカライズされた`netstat`に免疫のWindowsセンサ、Linux向け`/proc/net/tcp`フォールバック)、3 OSで423テスト全緑 |
""",
    "pt-BR": """| **v1.8.0** | **Os sinais profundos** — exfiltracao correlacionada a presenca (`UNATTENDED_EXFIL`), log forense inviolavel hash-encadeado (`/forensic/verify`), vereditos por linhagem, correlacao kill-chain (3 familias de detectores / 15 min = um incidente), DNS de sistema em um clique, governanca do trafego IA (21 provedores, shadow-AI), DLP local de segredos, vigilancia supply-chain (`POSTINSTALL_NET`), consultas `/ask` em linguagem natural, canarios anti-ransomware, honeyports LAN, resposta automatica opt-in, firewall DNS com upstream DoH, perfis por rede Wi-Fi, digest de privacidade compartilhavel |
| **v1.9.0** | **Flow DNA + ciclo de intrusao fechado** — metabolismo de rede por processo (`FLOW_DRIFT` explicavel), auditoria de governanca MCP (Cursor/Claude/Windsurf/Zed/VS Code/Devin), vigilancia de persistencia (`PERSISTENCE_NEW/MOD/DEL`), raio de blast em todo alerta critico, diff temporal (snapshots por hora, 48 h), endurecimento cross-plataforma (sensores Windows imunes ao `netstat` localizado, fallback `/proc/net/tcp` no Linux), 423 testes verdes nos 3 SO |
""",
    "zh-CN": """| **v1.8.0** | **深层信号** — 在场关联外泄检测(`UNATTENDED_EXFIL`)、哈希链接防篡改取证日志(`/forensic/verify`)、血统判定、杀伤链关联(3个检测器家族/15分钟=单一事件)、一键系统DNS、AI流量治理(21家提供商、shadow-AI)、机密本地DLP、供应链监视(`POSTINSTALL_NET`)、自然语言`/ask`查询、勒索软件金丝雀、LAN蜜罐端口、可选自动响应、带DoH上游的DNS防火墙、按Wi-Fi网络的配置文件、可分享的隐私摘要 |
| **v1.9.0** | **Flow DNA + 入侵周期闭环** — 每进程网络代谢(`FLOW_DRIFT`可解释)、MCP治理审计(Cursor/Claude/Windsurf/Zed/VS Code/Devin)、持久化监视(`PERSISTENCE_NEW/MOD/DEL`)、每个关键告警附带爆炸半径、时间穿越差分(每小时快照、48小时)、跨平台加固(Windows传感器免疫本地化`netstat`、Linux `/proc/net/tcp`回退)、3个操作系统上423项测试全绿 |
""",
}

ANCHORS = {
    "es": "## 🚧", "de": "## 🚧", "ru": "## 🚧", "ja": "## 🚧",
    "pt-BR": "## 🚧", "zh-CN": "## 🚧",
}

for lang, (old_tag, new_tag) in TAGLINES.items():
    path = f"README.{lang}.md"
    t = io.open(path, encoding="utf-8").read()
    if old_tag in t:
        t = t.replace(old_tag, new_tag, 1)
        io.open(path, "w", encoding="utf-8").write(t)
        print(f"tagline OK {path}")
    else:
        print(f"tagline MISS {path}")

for lang, rows in ROADMAP_ROWS.items():
    path = f"ROADMAP.{lang}.md"
    t = io.open(path, encoding="utf-8").read()
    if "v1.9.0" in t:
        print(f"roadmap SKIP {path}")
        continue
    anchor = None
    for line in t.splitlines():
        if line.startswith("## ") and ("v1.x" in line or "cours" in line or "Arbeit" in line or "прогрессе" in line or "進行中" in line or "andamento" in line or "进行中" in line):
            anchor = line
            break
    if anchor is None:
        for line in t.splitlines():
            if line.startswith("## ") and "Shipped" not in line and "✅" not in line:
                anchor = line
                break
    if anchor is None:
        print(f"roadmap ANCHOR-MISS {path}")
        continue
    t = t.replace(anchor, rows + "\n" + anchor, 1)
    io.open(path, "w", encoding="utf-8").write(t)
    print(f"roadmap OK {path} (anchor: {anchor[:40]})")
