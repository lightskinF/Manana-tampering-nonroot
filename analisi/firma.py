# -*- coding: utf-8 -*-
"""
firma.py - Lettura dei report CSV di Manana e applicazione della "firma" del paragrafo 3.2 della tesi.

Usa soltanto la libreria standard di Python (3.8 o successivo).

Definizione (formula (2) del paragrafo 3.2). Per ogni connessione c, aggregate le righe del report:
    s(c), r(c)  byte inviati e ricevuti,   t(c)  istante di apertura,   d(c)  destinazione (IP, porta)

    req(c)   <=>  s(c) > SOGLIA_INVIATI                     (connessione con richiesta)
    risp(c)  <=>  req(c) e r(c) > SOGLIA_RICEVUTI            (con risposta)
    cand(c)  <=>  req(c) e r(c) <= SOGLIA_RICEVUTI           (candidata)
    V(c)      =   { c' : d(c') = d(c) e |t(c') - t(c)| <= FINESTRA }     (c compresa)
    n_cand(c) =   numero di candidate in V(c)        n_risp(c) = numero di connessioni con risposta in V(c)

    firma(c) = completa   se cand(c) e n_cand(c) >= 2 e n_risp(c) = 0
               parziale   se cand(c), negli altri casi
               assente    se non cand(c)

Il report di Manana e' un registro di istantanee: una connessione compare in piu' righe e i byte di
ogni riga sono incrementi, quindi i totali si ottengono sommando le righe con la stessa porta sorgente,
lo stesso IP e la stessa porta di destinazione. Stato, durata e contatori di pacchetti NON sono usati
dalla firma (non affidabili: vedi paragrafo 3.2).
"""

import csv
import datetime
from collections import defaultdict

SOGLIA_INVIATI = 300     # byte inviati oltre i quali la connessione ha mandato una richiesta
SOGLIA_RICEVUTI = 200    # byte ricevuti sotto i quali non c'e' stata una risposta applicativa
FINESTRA = 120.0         # secondi, prima e dopo l'apertura di c


def leggi_orario(testo):
    """'2026-10-01T22:43:42.030Z' oppure '...+00:00' -> datetime con fuso UTC."""
    testo = testo.strip().replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(testo)
    except ValueError:
        return datetime.datetime.strptime(testo[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)


def leggi_manana(percorso, solo_ip=None):
    """Legge un CSV di Manana (separatore ',' oppure ';') e restituisce la lista delle connessioni TCP aggregate."""
    with open(percorso, newline="", encoding="utf-8-sig") as f:
        prima_riga = f.readline()
        f.seek(0)
        separatore = ";" if prima_riga.count(";") > prima_riga.count(",") else ","
        connessioni = {}
        for riga in csv.DictReader(f, delimiter=separatore):
            if riga["IPProto"].strip() != "6":
                continue                                           # solo TCP
            if solo_ip and riga["DstIp"] != solo_ip:
                continue
            chiave = (riga["SrcPort"], riga["DstIp"], riga["DstPort"])
            c = connessioni.get(chiave)
            if c is None:
                c = connessioni[chiave] = {
                    "srcport": riga["SrcPort"], "dstip": riga["DstIp"], "dstport": int(riga["DstPort"]),
                    "inviati": 0, "ricevuti": 0, "inizio": None, "fine": None,
                    "app": riga.get("App", ""), "info": "", "righe": 0, "stati": []}
            c["inviati"] += int(riga["BytesSent"])
            c["ricevuti"] += int(riga["BytesRcvd"])
            c["righe"] += 1
            c["stati"].append(riga.get("Status", ""))
            inizio, fine = leggi_orario(riga["FirstSeen"]), leggi_orario(riga["LastSeen"])
            if c["inizio"] is None or inizio < c["inizio"]:
                c["inizio"] = inizio
            if c["fine"] is None or fine > c["fine"]:
                c["fine"] = fine
            if not c["info"] and riga.get("Info"):
                c["info"] = riga["Info"]
    return list(connessioni.values())


def applica_firma(connessioni, s_soglia=SOGLIA_INVIATI, r_soglia=SOGLIA_RICEVUTI, finestra=FINESTRA):
    """Aggiunge a ogni connessione i campi req, risp, cand, n_cand, n_risp, firma (formula (2))."""
    per_destinazione = defaultdict(list)
    for c in connessioni:
        c["req"] = c["inviati"] > s_soglia
        c["risp"] = c["req"] and c["ricevuti"] > r_soglia
        c["cand"] = c["req"] and c["ricevuti"] <= r_soglia
        per_destinazione[(c["dstip"], c["dstport"])].append(c)
    for gruppo in per_destinazione.values():
        for c in gruppo:
            vicine = [x for x in gruppo if abs((x["inizio"] - c["inizio"]).total_seconds()) <= finestra]
            c["n_cand"] = sum(1 for x in vicine if x["cand"])
            c["n_risp"] = sum(1 for x in vicine if x["risp"])
            if not c["cand"]:
                c["firma"] = "assente"
            elif c["n_cand"] >= 2 and c["n_risp"] == 0:
                c["firma"] = "completa"
            else:
                c["firma"] = "parziale"
    return per_destinazione
