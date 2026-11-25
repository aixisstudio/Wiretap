#!/usr/bin/env python3
"""Restore proper diacritics in the v1.9 blocks of es/de/pt-BR docs.

The original files already use correct unicode; only the freshly inserted
ASCII-safe blocks need fixing. Replacements use word-boundary regex, applied
to README + ROADMAP per language."""
import io, re

FIXES = {
    "es": [
        ("senales", "señales"), ("Senal", "Señal"), ("senal", "señal"),
        ("exfiltracion", "exfiltración"), ("intrusion", "intrusión"),
        ("clasica", "clásica"), ("maquina", "máquina"),
        ("investigacion", "investigación"), ("exportacion", "exportación"),
        ("deteccion", "detección"), ("suspension", "suspensión"),
        ("instalacion", "instalación"), ("evaluacion", "evaluación"),
        ("exposicion", "exposición"), ("verificacion", "verificación"),
        ("correlacion", "correlación"), ("unico", "único"),
        ("automatico", "automático"), ("automatica", "automática"),
        ("criticas", "críticas"), ("rafagas", "ráfagas"),
        ("entropia", "entropía"), ("auditoria", "auditoría"),
        ("conexion", "conexión"), ("metodos", "métodos"),
        ("estatico", "estático"), ("delecion", "deleción"),
        ("retencion", "retención"), ("aparecio", "apareció"),
    ],
    "de": [
        ("wahrend", "während"), ("Wahrend", "Während"),
        ("grossen", "großen"), ("Grosse", "Größe"),
        ("geandert", "geändert"), ("loscht", "löscht"), ("Loschung", "Löschung"),
        ("erklaren", "erklären"), ("Uberwachung", "Überwachung"),
        ("uberwachung", "Überwachung"), ("Uberleben", "Überleben"),
        ("uberlebt", "überlebt"), ("verschlusseltem", "verschlüsseltem"),
        ("Naturlichsprachliche", "Natürlichsprachliche"),
        ("Koderdateien", "Köderdateien"), ("Hartung", "Härtung"),
        ("grun", "grün"), ("fur", "für"), ("Stundliche", "Stündliche"),
        ("stundliche", "stündliche"), ("gefingerprinted", "mit Fingerabdruck versehen"),
        ("Aufbewahrung", "Aufbewahrung"), ("Eingereicht", "eingereicht"),
        ("Absender", "Absender"),
    ],
    "pt-BR": [
        ("exfiltracao", "exfiltração"), ("presenca", "presença"),
        ("voce", "você"), ("maquina", "máquina"),
        ("avaliacao", "avaliação"), ("exposicao", "exposição"),
        ("sobrevivencia", "sobrevivência"), ("investigacao", "investigação"),
        ("delecao", "deleção"), ("verificacao", "verificação"),
        ("correlacao", "correlação"), ("unico", "único"),
        ("automatico", "automático"), ("automatica", "automática"),
        ("deteccao", "detecção"), ("exportacao", "exportação"),
        ("conteudo", "conteúdo"), ("lancadores", "lançadores"),
        ("superficie", "superfície"), ("instalacao", "instalação"),
        ("suspensao", "suspensão"), ("criticos", "críticos"),
        ("classica", "clássica"), ("intrusao", "intrusão"),
        ("razao", "razão"), ("saida", "saída"), ("apos", "após"),
        ("retencao", "retenção"), ("entropia", "entropia"),
    ],
}

for lang, pairs in FIXES.items():
    for kind in ("README", "ROADMAP"):
        path = f"{kind}.{lang}.md"
        try:
            t = io.open(path, encoding="utf-8").read()
        except FileNotFoundError:
            continue
        n = 0
        for a, b in pairs:
            t2, c = re.subn(r"(?<![A-Za-z])" + re.escape(a) + r"(?![A-Za-z])", b, t)
            if c:
                t = t2
                n += c
        io.open(path, "w", encoding="utf-8").write(t)
        print(f"{path}: {n} corrections")
print("done")
