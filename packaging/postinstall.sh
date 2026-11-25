#!/bin/sh
# EN: nfpm postinstall — create the dedicated service user and reload
#     systemd so the shipped unit is known. Never fails the install.
# FR: postinstall nfpm — crée l'utilisateur de service dédié et recharge
#     systemd pour que l'unité fournie soit connue. Ne fait jamais
#     échouer l'installation.
id wiretap >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin wiretap
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Enable with: systemctl enable --now wiretap"
