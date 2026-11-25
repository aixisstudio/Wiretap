# Empacotamento Linux

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | [Deutsch](PACKAGING.de.md) | [Русский](PACKAGING.ru.md) | [日本語](PACKAGING.ja.md) | **Português** | [中文](PACKAGING.zh-CN.md)

## Formatos publicados

| Formato | Arquivo | Notas |
|---|---|---|
| AppImage | `Wiretap-x86_64.AppImage` | portátil, requer `libfuse2`; info de atualização via `latest-linux.yml` |
| deb | `wiretap-linux-amd64.deb` | instalação padrão Debian/Ubuntu |
| snap | `Wiretap-amd64.snap` | confinamento estrito — veja abaixo |

## Snap — captura de pacotes sob confinamento

O snap é construído pelo electron-builder (`linux.target` inclui `"snap"`)
em confinamento estrito. A captura usa sockets `AF_PACKET`, que a
interface `network-observe` concede (o mesmo modelo do snap `tcpdump`).
Após instalar um `.snap` local:

```bash
sudo snap install --dangerous Wiretap-amd64.snap
sudo snap connect wiretap:network-observe   # concede leitura AF_PACKET
```

Sem essa conexão a UI roda mas a captura fica vazia. Uma publicação na
Store conectaria a interface automaticamente após revisão humana; até lá
a conexão manual é obrigatória.

## Flatpak — deliberadamente não publicado

A sandbox do Flatpak não pode conceder acesso `AF_PACKET`: nenhum portal
ou combinação de `finish-args` expõe a captura bruta, e a atribuição por
processo via `psutil` precisa de visibilidade do `/proc` do host que a
sandbox nega. Publicar um Flatpak geraria uma UI bonita incapaz de ver um
pacote — preferimos não publicar um app quebrado a fingir. Se o flathub
um dia criar uma permissão de captura, reavaliaremos.

## rpm + fórmula Homebrew + pipeline de release

O workflow `release.yml` (em cada tag `v*` ou `workflow_dispatch`) executa quatro jobs: **nfpm** constrói `wiretap-linux-amd64.rpm` (nfpm v2.48, `packaging/nfpm.yaml`); **homebrew** envia `Formula/wiretap.rb` ao tap `aixisstudio/homebrew-tap` e instala o daemon headless `wiretapd` (`brew install aixisstudio/tap/wiretap`, exige `HOMEBREW_TAP_TOKEN`); **winget** submete `Wiretap-Setup-*.exe` via winget-releaser quando o asset existe (`WINGET_TOKEN`); **chocolatey** empacota/publica `installer/Wiretap.nuspec` se `CHOCO_API_KEY` estiver configurada.
