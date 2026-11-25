# Пакетирование для Linux

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | [Deutsch](PACKAGING.de.md) | **Русский** | [日本語](PACKAGING.ja.md) | [Português](PACKAGING.pt-BR.md) | [中文](PACKAGING.zh-CN.md)

## Выпускаемые форматы

| Формат | Файл | Примечания |
|---|---|---|
| AppImage | `Wiretap-x86_64.AppImage` | портабельный, нужен `libfuse2`; информация обновлений через `latest-linux.yml` |
| deb | `wiretap-linux-amd64.deb` | стандартная установка Debian/Ubuntu |
| snap | `Wiretap-amd64.snap` | строгое ограничение (strict) — см. ниже |

## Snap — захват пакетов под confinement

Snap собирается electron-builder'ом (`linux.target` включает `"snap"`) в
режиме strict. Захват использует сокеты `AF_PACKET`, доступ к которым даёт
интерфейс `network-observe` (та же модель, что у snap `tcpdump`). После
установки локального `.snap`:

```bash
sudo snap install --dangerous Wiretap-amd64.snap
sudo snap connect wiretap:network-observe   # даёт чтение AF_PACKET
```

Без этого подключения UI работает, но захват пуст. Публикация в Store
подключила бы интерфейс автоматически после ручной проверки; до тех пор
нужно ручное подключение.

## Flatpak — сознательно не выпускается

Песочница Flatpak не может дать доступ `AF_PACKET`: ни portal, ни
комбинация `finish-args` не открывают сырой захват, а атрибуция процессов
через `psutil` требует видимости хостового `/proc`, которую песочница не
даёт. Flatpak выпустил бы красивый UI, неспособный увидеть ни одного
пакета — лучше не публиковать сломанное приложение, чем имитировать.
Если flathub когда-нибудь добавит разрешение на захват — пересмотрим.

## rpm + формула Homebrew + релиз-пайплайн

Workflow `release.yml` (на каждый тег `v*` или `workflow_dispatch`) выполняет четыре джоба: **nfpm** собирает `wiretap-linux-amd64.rpm` (nfpm v2.48, `packaging/nfpm.yaml`); **homebrew** пушит `Formula/wiretap.rb` в tap `aixisstudio/homebrew-tap` и ставит headless-демон `wiretapd` (`brew install aixisstudio/tap/wiretap`, нужен `HOMEBREW_TAP_TOKEN`); **winget** отправляет `Wiretap-Setup-*.exe` через winget-releaser, когда asset существует (`WINGET_TOKEN`); **chocolatey** пакует/публикует `installer/Wiretap.nuspec`, если задан `CHOCO_API_KEY`.
