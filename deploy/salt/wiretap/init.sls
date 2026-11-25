# Wiretap — SaltStack state skeleton (community maintained, help wanted)
# EN: Same three primitives — user, tree + venv, wiretap.toml, unit.
#     Pillar keys: wiretap:syslog_addr, wiretap:peers, …
# FR: Mêmes trois primitives — utilisateur, arbre + venv, wiretap.toml,
#     unité. Clés pillar : wiretap:syslog_addr, wiretap:peers, …

wiretap-user:
  user.present:
    - name: wiretap
    - system: True
    - createhome: False
    - shell: /usr/sbin/nologin

wiretap-dirs:
  file.directory:
    - names:
      - /opt/wiretap
      - /etc/wiretap
      - /var/lib/wiretap
    - require:
      - user: wiretap-user

wiretap-backend:
  file.recurse:
    - name: /opt/wiretap/backend
    - source: salt://wiretap/backend
    - dir_mode: "0755"
    - file_mode: "0644"
    - require:
      - file: wiretap-dirs

wiretap-venv:
  virtualenv.managed:
    - name: /opt/wiretap/backend/env
    - requirements: /opt/wiretap/backend/requirements.txt
    - require:
      - file: wiretap-backend

wiretap-config:
  file.managed:
    - name: /etc/wiretap/wiretap.toml
    - source: salt://wiretap/files/wiretap.toml.jinja
    - template: jinja
    - mode: "0640"
    - user: root
    - group: wiretap
    - watch_in:
      - service: wiretap-service

wiretap-unit:
  file.managed:
    - name: /etc/systemd/system/wiretap.service
    - source: salt://wiretap/files/wiretap.service
    - mode: "0644"
    - require:
      - file: wiretap-dirs
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: wiretap-unit

wiretap-service:
  service.running:
    - name: wiretap
    - enable: True
    - require:
      - virtualenv: wiretap-venv
      - file: wiretap-config
      - module: wiretap-unit
