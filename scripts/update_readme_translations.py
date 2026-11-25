#!/usr/bin/env python3
"""Insert the v1.9 deep-signals section + repositioning into the 6 translated READMEs.

EN/FR live inline in README.md (already updated); this propagates condensed
native-language versions to es/de/ru/ja/pt-BR/zh-CN, inserted right before
each file's features table. Idempotent: skips files already carrying the block.
"""

# Per-language: (file, features-header-anchor, intro-old, intro-new, deep-block)
# deep-block rows: name | description — condensed but complete.

DATA = {
    "es": {
        "anchor": "### Funciones",
        "intro_old": None,  # intro update optional per-language phrasing varies
        "block": """### Las senales profundas — v1.9

Todo lo que ve una herramienta de red clasica, mas todo lo que no puede ver. El ciclo de intrusion cerrado de punta a punta:

| Senal | Que hace |
|---|---|
| **Exfiltracion correlacionada con presencia** | 5 MB hacia un proveedor de IA mientras escribes eres tu con tu IDE; los mismos 5 MB mientras estas ausente son otra cosa actuando en tu nombre. Tiempo de inactividad del teclado leido sin privilegios — `UNATTENDED_EXFIL`. Nadie mas cruza los flujos con la presencia humana |
| **Flow DNA** | Metabolismo de red por proceso — rafagas, ritmo, ratio saliente:entrante, entropia de destinos — aprendido en silencio y luego puntuado. Una app comprometida conserva su nombre pero cambia de metabolismo. Las alertas `FLOW_DRIFT` se explican solas |
| **Veredictos por linaje** | `navegador -> sh -> curl -> evil.bin` cuenta la historia que un nombre de proceso oculta — puntuacion de ascendencia con frases de evidencia |
| **Vigilancia de persistencia** | LaunchAgents, claves Run, systemd, cron — cada mecanismo de autoarranque huellado y comparado cada 5 min. Sobrevivir al reinicio es lo que el malware mas necesita; `PERSISTENCE_NEW/MOD/DEL` |
| **Radio de impacto** | Cada alerta critica lleva una evaluacion de impacto calculada — destinos, exposicion IA, secretos al alcance, supervivencia al reinicio. Triage en una frase en vez de una investigacion |
| **Diff temporal** | «Que cambio en esta maquina desde el martes?» — snapshots horarios, retencion 48 h, aparecido/desaparecido/mutado en milisegundos |
| **Registro forense inviolable** | Cada alerta encadenada por hash a la anterior — un atacante que borra alertas rompe la cadena: el borrado mismo se vuelve evidencia. Verificacion offline en `/forensic/verify` |
| **Correlacion kill-chain** | 3 familias de detectores distintas sobre la misma entidad en 15 min no es ruido — es un incidente unico, narrado como timeline, que puede disparar el lockdown automatico |
| **Gobernanza del trafico IA** | Conteo de bytes por (proveedor, proceso) en 21 proveedores de IA, alertas shadow-AI al primer contacto, deteccion de exportacion masiva — solo metadatos, nunca el contenido |
| **Vigilancia de secretos** | DLP local — tus claves API cosechadas de env/dotfiles (los valores nunca salen de la RAM), alertadas cuando cruzan la red en claro o fluyen a un proveedor de IA |
| **Gobernanza MCP** | Auditoria de riesgo de cada servidor MCP declarado en Cursor / Claude / Windsurf / Zed / VS Code / Devin — lanzadores download-and-run, acceso filesystem sin scope: la nueva superficie de ataque de los agentes IA |
| **Vigilancia supply-chain** | `POSTINSTALL_NET` — un proceso nunca visto que se conecta minutos despues de una instalacion es la firma del compromiso supply-chain |
| **Canarios + honeyports + respuesta auto** | Archivos trampa anti-ransomware, listeners pasivos LAN en telnet/SMB/RDP/VNC, lockdown o suspension opt-in en alertas criticas — deteccion que actua |
| **Firewall DNS + perfiles de red** | Proxy DNS filtrante con upstream DoH cifrado y blocklists curadas; perfiles de firewall conmutados automaticamente por SSID/BSSID Wi-Fi |
| **Consultas en lenguaje natural** | `/ask` — «algo hablo con Rusia esta semana?» respondido deterministicamente desde SQLite, nunca alucinado |

""",
    },
    "de": {
        "anchor": "### Funktionen",
        "intro_old": None,
        "block": """### Die tiefen Signale — v1.9

Alles, was ein klassisches Netzwerk-Tool sehen kann, plus alles, was es nicht sehen kann. Der Intrusion-Zyklus, Ende-zu-Ende geschlossen:

| Signal | Was es tut |
|---|---|
| **Anwesenheitskorrelierte Exfiltration** | 5 MB zu einem KI-Anbieter wahrend du tippst bist du mit deiner IDE; dieselben 5 MB wahrend deiner Abwesenheit sind etwas anderes, das in deinem Namen handelt. OS-Input-Idle-Zeit ohne Privilegien gelesen — `UNATTENDED_EXFIL`. Niemand sonst korreliert Flows mit menschlicher Anwesenheit |
| **Flow DNA** | Netzwerk-Metabolismus pro Prozess — Burst-Grossen, Rhythmus, Out:In-Ratio, Ziel-Entropie — still gelernt, dann bewertet. Eine kompromittierte App behalt ihren Namen, aber andert ihren Metabolismus. `FLOW_DRIFT`-Alarme erklaren sich selbst |
| **Herkunfts-Verdikte** | `browser -> sh -> curl -> evil.bin` erzahlt die Geschichte, die ein blosser Prozessname verbirgt — Abstammungs-Scoring mit Beweissatzen |
| **Persistenz-Uberwachung** | LaunchAgents, Run-Keys, systemd, cron — jeder Autostart-Mechanismus gefingerabdruckt und alle 5 Minuten verglichen. Den Neustart zu uberleben ist, was Malware am meisten braucht; `PERSISTENCE_NEW/MOD/DEL` |
| **Blast-Radius** | Jeder kritische Alarm tragt eine berechnete Impact-Bewertung — erreichte Ziele, KI-Exposition, erreichbare Secrets, Neustart-Uberleben. Triage in einem Satz statt einer Untersuchung |
| **Zeitreise-Diff** | „Was hat sich auf diesem Rechner seit Dienstag geandert?" — Stundliche Snapshots, 48 h Aufbewahrung, erschienen/verschwunden/verandert in Millisekunden |
| **Manipulationssicheres Forensik-Log** | Jeder Alarm per Hash an den vorherigen verkettet — ein Angreifer, der Alarme loscht, bricht die Kette: Die Loschung selbst wird zum Beweis. Offline-Verifikation unter `/forensic/verify` |
| **Kill-Chain-Korrelation** | 3 verschiedene Detektor-Familien auf derselben Entitat in 15 Min sind kein Rauschen — es ist ein einziger Vorfall, als Timeline erzahlt, der den automatischen Lockdown auslosen kann |
| **KI-Traffic-Governance** | Byte-Abrechnung pro (Anbieter, Prozess) uber 21 KI-Anbieter, Shadow-AI-Erstkontakt-Alarme, Massenexport-Erkennung — nur Metadaten, niemals Inhalte |
| **Secret-Egress-Watch** | Lokale DLP — API-Keys aus Env/Dotfiles geerntet (Werte verlassen nie den RAM), alarmiert wenn sie im Klartext die Leitung uberqueren oder zu einem KI-Anbieter fliessen |
| **MCP-Governance** | Risiko-Audit jedes MCP-Servers aus Cursor / Claude / Windsurf / Zed / VS Code / Devin — Download-and-run-Launcher, unbegrenzter Dateizugriff: die neue Angriffsflache der KI-Agenten |
| **Supply-Chain-Watch** | `POSTINSTALL_NET` — ein nie gesehener Prozess, der Minuten nach einer Installation ins Netz geht, ist die Supply-Chain-Kompromittierungs-Signatur |
| **Canaries + Honeyports + Auto-Response** | Ransomware-Koderdateien, passive LAN-Listener auf telnet/SMB/RDP/VNC, opt-in Lockdown oder Prozess-Suspension bei kritischen Alarmen — Erkennung, die handelt |
| **DNS-Firewall + Netzwerkprofile** | Filtern der DNS-Proxy mit verschlusseltem DoH-Upstream und kuratierten Blocklists; Firewall-Profile wechseln automatisch pro WLAN-SSID/BSSID |
| **Naturlichsprachliche Abfragen** | `/ask` — „hat etwas diese Woche mit Russland gesprochen?" — deterministisch aus SQLite beantwortet, nie halluziniert |

""",
    },
    "ru": {
        "anchor": "### Возможности",
        "intro_old": None,
        "block": """### Глубокие сигналы — v1.9

Всё, что видит классический сетевой инструмент, плюс всё, чего он не видит. Цикл вторжения, закрытый от начала до конца:

| Сигнал | Что делает |
|---|---|
| **Эксфильтрация с корреляцией присутствия** | 5 МБ к AI-провайдеру, пока вы печатаете — это вы с вашей IDE; те же 5 МБ в ваше отсутствие — нечто действует от вашего имени. Время простоя ввода читается без привилегий — `UNATTENDED_EXFIL`. Больше никто не связывает потоки с присутствием человека |
| **Flow DNA** | Сетевой метаболизм каждого процесса — размеры всплесков, ритм, соотношение исходящего к входящему, энтропия назначений — обучается молча, затем оценивается. Скомпрометированное приложение сохраняет имя, но меняет метаболизм. Алерты `FLOW_DRIFT` объясняют себя сами |
| **Вердикты по происхождению** | `браузер -> sh -> curl -> evil.bin` рассказывает историю, которую скрывает голое имя процесса — скоринг родословной с доказательными фразами |
| **Наблюдение за персистентностью** | LaunchAgents, ключи Run, systemd, cron — каждый механизм автозапуска снимается с отпечатка и сравнивается каждые 5 минут. Пережить перезагрузку — главная потребность малвари; `PERSISTENCE_NEW/MOD/DEL` |
| **Радиус поражения** | Каждый критический алерт несёт вычисленную оценку ущерба — достигнутые назначения, AI-экспозиция, доступные секреты, переживание перезагрузки. Триаж одной фразой вместо расследования |
| **Разница во времени** | «Что изменилось на этой машине со вторника?» — ежечасные снапшоты, хранение 48 ч, появилось/исчезло/мутировало за миллисекунды |
| **Неподделываемый форензик-журнал** | Каждый алерт хеш-связан с предыдущим — атакующий, стирающий алерты, ломает цепь: само удаление становится доказательством. Офлайн-проверка на `/forensic/verify` |
| **Корреляция kill-chain** | 3 разных семейства детекторов на одной сущности за 15 минут — не шум, а один инцидент, рассказанный как таймлайн, способный запустить автоматический lockdown |
| **Управление AI-трафиком** | Подсчёт байтов по (провайдер, процесс) для 21 AI-провайдера, алерты shadow-AI при первом контакте, детект массового экспорта — только метаданные, никогда содержимое |
| **Наблюдение за секретами** | Локальный DLP — ваши API-ключи собраны из env/dotfiles (значения никогда не покидают RAM), алерт когда они пересекают сеть в открытом виде или текут к AI-провайдеру |
| **Управление MCP** | Аудит рисков каждого MCP-сервера из Cursor / Claude / Windsurf / Zed / VS Code / Devin — загрузчики download-and-run, неограниченный доступ к файлам: новая поверхность атаки AI-агентов |
| **Наблюдение за supply-chain** | `POSTINSTALL_NET` — невиданный процесс, выходящий в сеть через минуты после установки — сигнатура компрометации цепочки поставок |
| **Канарейки + ханипорты + автоответ** | Файлы-приманки против ransomware, пассивные LAN-слушатели на telnet/SMB/RDP/VNC, opt-in lockdown или приостановка процесса при критических алертах — детект, который действует |
| **DNS-файрвол + сетевые профили** | Фильтрующий DNS-прокси с шифрованным DoH-апстримом и курируемыми блоклистами; профили файрвола переключаются автоматически по SSID/BSSID Wi-Fi |
| **Запросы на естественном языке** | `/ask` — «что-то говорило с Россией на этой неделе?» — детерминистический ответ из SQLite, никогда не галлюцинация |

""",
    },
    "ja": {
        "anchor": "### 機能",
        "intro_old": None,
        "block": """### ディープシグナル — v1.9

従来のネットワークツールが見えるすべてに加えて、見えないすべても。侵入サイクルを端から端まで閉じます:

| シグナル | 内容 |
|---|---|
| **プレゼンス相関エクスフィルトレーション** | タイピング中のAIプロバイダへの5MBはIDEを使うあなた自身。不在中の同じ5MBは、あなたの名で動く何か他のもの。OSの入力アイドル時間を権限ゼロで読み取り — `UNATTENDED_EXFIL`。フローと人間のプレゼンスを相関させるのは他にいません |
| **Flow DNA** | プロセスごとのネットワーク代謝 — バーストサイズ、リズム、送信:受信比、宛先エントロピー — をサイレント学習しスコアリング。侵害されたアプリは名前を保ちますが代謝が変わります。`FLOW_DRIFT`アラートは自己説明的です |
| **系譜による判定** | `ブラウザ -> sh -> curl -> evil.bin` は裸のプロセス名が隠す物語を語ります — 証拠文付きの祖先スコアリング |
| **永続化の監視** | LaunchAgents、Runキー、systemd、cron — すべての自動起動メカニズムをフィンガープリントし5分ごとに差分検出。再起動を生き残ることはマルウェアが最も必要とするものです。`PERSISTENCE_NEW/MOD/DEL` |
| **ブラスト半径** | すべてのクリティカルアラートに計算済みの影響評価が付随 — 到達宛先、AI露出、手の届くシークレット、再起動生存。調査ではなく一文でトリアージ |
| **タイムトラベル差分** | 「火曜日からこのマシンで何が変わった?」— 毎時スナップショット、48時間保持、出現/消失/変異をミリ秒で |
| **改ざん検知フォレンジックログ** | 各アラートは前のアラートにハッシュチェーン — アラートを消す攻撃者はチェーンを壊し、削除そのものが証拠になります。`/forensic/verify`でオフライン検証 |
| **キルチェーン相関** | 15分以内に同一エンティティで3つの異なる検出器ファミリーはノイズではなく、タイムラインとして語られる1つのインシデント — 自動ロックダウンをトリガー可能 |
| **AIトラフィックガバナンス** | 21のAIプロバイダについて(プロバイダ、プロセス)ごとのバイト計量、shadow-AI初回接触アラート、大量エクスポート検出 — メタデータのみ、ペイロードは決して見ません |
| **シークレット監視** | ローカルDLP — env/dotfilesから収穫されたAPIキー(値はRAMを離れません)が平文で回線を横断したりAIプロバイダに流れるとアラート |
| **MCPガバナンス** | Cursor / Claude / Windsurf / Zed / VS Code / Devin で宣言されたすべてのMCPサーバのリスク監査 — download-and-runランチャー、スコープなしのファイルアクセス: AIエージェントの新しい攻撃面 |
| **サプライチェーン監視** | `POSTINSTALL_NET` — インストールから数分以内に通信する初見のプロセスはサプライチェーン侵害のシグネチャ |
| **カナリア + ハニーポート + 自動対応** | ランサムウェア用トリップワイヤファイル、telnet/SMB/RDP/VNCのパッシブLANリスナー、クリティカルアラート時のopt-inロックダウン/プロセス停止 — 行動する検出 |
| **DNSファイアウォール + ネットワークプロファイル** | 暗号化DoHアップストリームとキュレーション済みブロックリストのフィルタリングDNSプロキシ。Wi-Fi SSID/BSSIDごとにファイアウォールプロファイルを自動切替 |
| **自然言語クエリ** | `/ask` — 「今週ロシアと通信したものは?」SQLiteから決定論的に回答、幻覚なし |

""",
    },
    "pt-BR": {
        "anchor": "### Funcionalidades",
        "intro_old": None,
        "block": """### Os sinais profundos — v1.9

Tudo o que uma ferramenta de rede classica ve, mais tudo o que ela nao ve. O ciclo de intrusao fechado de ponta a ponta:

| Sinal | O que faz |
|---|---|
| **Exfiltracao correlacionada a presenca** | 5 MB para um provedor de IA enquanto voce digita e voce usando sua IDE; os mesmos 5 MB na sua ausencia sao outra coisa agindo em seu nome. Tempo ocioso de input lido sem privilegios — `UNATTENDED_EXFIL`. Ninguem mais cruza fluxos com presenca humana |
| **Flow DNA** | Metabolismo de rede por processo — tamanhos de burst, ritmo, razao saida:entrada, entropia de destinos — aprendido em silencio e depois pontuado. Um app comprometido mantem o nome mas muda o metabolismo. Alertas `FLOW_DRIFT` se autoexplicam |
| **Vereditos por linhagem** | `navegador -> sh -> curl -> evil.bin` conta a historia que um nome de processo esconde — scoring de ascendencia com frases de evidencia |
| **Vigilancia de persistencia** | LaunchAgents, chaves Run, systemd, cron — cada mecanismo de autostart fingerprintado e comparado a cada 5 min. Sobreviver ao reboot e o que o malware mais precisa; `PERSISTENCE_NEW/MOD/DEL` |
| **Raio de blast** | Todo alerta critico carrega uma avaliacao de impacto calculada — destinos alcancados, exposicao IA, segredos ao alcance, sobrevivencia ao reboot. Triage em uma frase em vez de investigacao |
| **Diff temporal** | «O que mudou nesta maquina desde terca?» — snapshots por hora, retencao 48 h, aparecido/sumido/mutado em milissegundos |
| **Log forense inviolavel** | Cada alerta hash-encadeado ao anterior — um atacante que apaga alertas quebra a cadeia: a delecao vira evidencia. Verificacao offline em `/forensic/verify` |
| **Correlacao kill-chain** | 3 familias de detectores distintas na mesma entidade em 15 min nao e ruido — e um incidente unico, narrado como timeline, que pode disparar o lockdown automatico |
| **Governanca do trafego IA** | Contagem de bytes por (provedor, processo) em 21 provedores de IA, alertas shadow-AI no primeiro contato, deteccao de exportacao massiva — so metadados, nunca conteudo |
| **Vigilancia de segredos** | DLP local — suas chaves API colhidas de env/dotfiles (valores nunca saem da RAM), alertadas quando cruzam a rede em claro ou fluem para um provedor de IA |
| **Governanca MCP** | Auditoria de risco de cada servidor MCP declarado em Cursor / Claude / Windsurf / Zed / VS Code / Devin — lancadores download-and-run, acesso a filesystem sem escopo: a nova superficie de ataque dos agentes IA |
| **Vigilancia supply-chain** | `POSTINSTALL_NET` — um processo nunca visto que se conecta minutos apos uma instalacao e a assinatura do comprometimento supply-chain |
| **Canarios + honeyports + resposta auto** | Arquivos-armadilha anti-ransomware, listeners passivos LAN em telnet/SMB/RDP/VNC, lockdown ou suspensao opt-in em alertas criticos — deteccao que age |
| **Firewall DNS + perfis de rede** | Proxy DNS filtrante com upstream DoH criptografado e blocklists curadas; perfis de firewall trocados automaticamente por SSID/BSSID Wi-Fi |
| **Consultas em linguagem natural** | `/ask` — «algo falou com a Russia esta semana?» respondido deterministicamente do SQLite, nunca alucinado |

""",
    },
    "zh-CN": {
        "anchor": "### 功能特性",
        "intro_old": None,
        "block": """### 深层信号 — v1.9

传统网络工具能看到的一切,再加上它看不到的一切。入侵周期端到端闭环:

| 信号 | 作用 |
|---|---|
| **在场关联外泄检测** | 你打字时流向AI提供商的5MB是你自己在用IDE;你不在时同样的5MB是别的东西在以你的名义行动。以零权限读取操作系统输入空闲时间 — `UNATTENDED_EXFIL`。没有别的工具把网络流量和人类在场关联起来 |
| **Flow DNA** | 每个进程的网络代谢 — 突发大小、节奏、收发比、目的地熵 — 静默学习后评分。被入侵的应用名字不变但代谢改变。`FLOW_DRIFT`告警自我解释 |
| **血统判定** | `浏览器 -> sh -> curl -> evil.bin` 讲述裸进程名隐藏的故事 — 带证据句子的祖先评分 |
| **持久化监视** | LaunchAgents、Run键、systemd、cron — 每个自启动机制都打指纹并每5分钟比对。重启后存活是恶意软件最需要的;`PERSISTENCE_NEW/MOD/DEL` |
| **爆炸半径** | 每个关键告警都附带计算好的影响评估 — 到达的目的地、AI暴露、可触及的机密、重启存活。一句话分诊取代调查 |
| **时间穿越差分** | 「这台机器自周二以来改变了什么?」— 每小时快照、48小时保留、毫秒级出现/消失/变异 |
| **防篡改取证日志** | 每条告警与前一条哈希链接 — 删除告警的攻击者会弄断链条:删除本身就成为证据。`/forensic/verify` 离线验证 |
| **杀伤链关联** | 15分钟内同一实体上3个不同检测器家族不是噪音 — 而是一个以时间线叙述的单一事件,可触发自动锁定 |
| **AI流量治理** | 21家AI提供商按(提供商,进程)字节计量、shadow-AI首次接触告警、批量导出检测 — 仅元数据,绝不读取内容 |
| **机密外泄监视** | 本地DLP — 从env/dotfiles收集的API密钥(值永不离开内存),当它们以明文穿越网络或流向AI提供商时告警 |
| **MCP治理** | 审计 Cursor / Claude / Windsurf / Zed / VS Code / Devin 中声明的每个MCP服务器 — 下载即运行启动器、无范围文件访问:AI代理的新攻击面 |
| **供应链监视** | `POSTINSTALL_NET` — 安装后几分钟内联网的从未见过的进程是供应链入侵的特征 |
| **金丝雀 + 蜜罐端口 + 自动响应** | 反勒索软件诱饵文件、telnet/SMB/RDP/VNC被动LAN监听、关键告警时可选锁定/进程挂起 — 会行动的检测 |
| **DNS防火墙 + 网络配置文件** | 带加密DoH上游和精选拦截列表的过滤DNS代理;按Wi-Fi SSID/BSSID自动切换防火墙配置文件 |
| **自然语言查询** | `/ask` — 「这周有什么东西和俄罗斯通信了吗?」从SQLite确定性回答,绝不幻觉 |

""",
    },
}

import io, sys

changed = []
for lang, cfg in DATA.items():
    path = f"README.{lang}.md"
    try:
        t = io.open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"MISSING {path}")
        continue
    if "deep-signals" in t or "v1.9" in t.split("##")[1][:200] if "##" in t else False:
        pass  # cheap check below is authoritative
    anchor = cfg["anchor"]
    if anchor not in t:
        print(f"ANCHOR-MISS {path}: {anchor!r}")
        continue
    if "v1.9" in t[:len(t)//3]:
        print(f"SKIP {path} (already has v1.9 block)")
        continue
    t = t.replace(anchor + "\n", cfg["block"] + anchor + "\n", 1)
    io.open(path, "w", encoding="utf-8").write(t)
    changed.append(path)
    print(f"OK {path}")

print("changed:", len(changed))
