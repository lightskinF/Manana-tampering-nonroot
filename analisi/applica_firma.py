# -*- coding: utf-8 -*-
"""
applica_firma.py - Applica la firma del paragrafo 3.2 a uno o piu' report CSV di Manana.

Uso:
    python applica_firma.py report1.csv [report2.csv ...]
    python applica_firma.py report.csv --out connessioni.csv      (una riga per connessione, con la sua firma)
    python applica_firma.py report.csv --solo-ip 10.0.2.2          (solo le connessioni verso quell'IP)
    python applica_firma.py report.csv --tutte                     (mostra anche le destinazioni senza candidate)

Per ogni file stampa: connessioni TCP, connessioni con richiesta, candidate, e le destinazioni che
hanno almeno una connessione candidata, con i profili byte inviati/ricevuti e l'etichetta di firma.
Le soglie e la finestra sono quelle della tesi (300 byte, 200 byte, 120 s) e si possono cambiare per
prova con --inviati, --ricevuti, --finestra, ma i risultati della tesi si ottengono con i valori di default.

La firma segnala un pattern (richiesta senza risposta applicativa, ripetuta verso la stessa destinazione,
senza successi vicini): non attribuisce una causa e non e' una prova di censura.
"""

import argparse
import collections
import csv
import sys

import firma as F


def riepilogo(connessioni, tutte):
    req = [c for c in connessioni if c["req"]]
    cand = [c for c in req if c["cand"]]
    et = collections.Counter(c["firma"] for c in cand)
    print(f"Connessioni TCP: {len(connessioni)} | con richiesta (> {F.SOGLIA_INVIATI} byte inviati): {len(req)} | "
          f"candidate: {len(cand)} | firma completa: {et['completa']}, parziale: {et['parziale']}")
    per_dest = collections.defaultdict(list)
    for c in connessioni:
        per_dest[(c["dstip"], c["dstport"])].append(c)
    stampate = 0
    for (ip, porta), gruppo in sorted(per_dest.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        r = [c for c in gruppo if c["req"]]
        k = [c for c in r if c["cand"]]
        if not r or (not k and not tutte):
            continue
        nome = next((c["info"] for c in gruppo if c["info"]), "")
        profili = collections.Counter((c["inviati"], c["ricevuti"]) for c in k)
        profili_txt = "; ".join(f"{i}/{ric} x{n}" for (i, ric), n in sorted(profili.items())) or "-"
        etich = collections.Counter(c["firma"] for c in k)
        con_risp = sum(1 for c in r if c["risp"])
        print(f"  {ip}:{porta} [{nome}]  con richiesta {len(r)}, candidate {len(k)} "
              f"(completa {etich['completa']}, parziale {etich['parziale']}), con risposta {con_risp}")
        if k:
            print(f"      profili candidate (inviati/ricevuti): {profili_txt}")
        stampate += 1
    if not stampate:
        print("  (nessuna destinazione con connessioni candidate)")


def main():
    ap = argparse.ArgumentParser(description="Applica la firma del paragrafo 3.2 ai report CSV di Manana")
    ap.add_argument("csv", nargs="+", help="uno o piu' report CSV esportati da Manana")
    ap.add_argument("--solo-ip", help="considera solo questo IP di destinazione")
    ap.add_argument("--tutte", action="store_true", help="mostra anche le destinazioni senza candidate")
    ap.add_argument("--inviati", type=int, default=F.SOGLIA_INVIATI)
    ap.add_argument("--ricevuti", type=int, default=F.SOGLIA_RICEVUTI)
    ap.add_argument("--finestra", type=float, default=F.FINESTRA)
    ap.add_argument("--out", help="scrive qui un CSV con una riga per connessione")
    a = ap.parse_args()
    F.SOGLIA_INVIATI, F.SOGLIA_RICEVUTI = a.inviati, a.ricevuti

    tutte_conn = []
    for percorso in a.csv:
        print(f"\n=== {percorso}")
        conn = F.leggi_manana(percorso, a.solo_ip)
        F.applica_firma(conn, a.inviati, a.ricevuti, a.finestra)
        riepilogo(conn, a.tutte)
        for c in conn:
            c["file"] = percorso
        tutte_conn.extend(conn)

    if a.out:
        campi = ["file", "dstip", "dstport", "srcport", "app", "info", "inizio", "inviati", "ricevuti",
                 "req", "risp", "cand", "n_cand", "n_risp", "firma"]
        with open(a.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=campi, extrasaction="ignore")
            w.writeheader()
            for c in sorted(tutte_conn, key=lambda c: (c["file"], c["dstip"], c["dstport"], c["inizio"])):
                w.writerow({**c, "inizio": c["inizio"].isoformat()})
        print(f"\nScritto {a.out}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
