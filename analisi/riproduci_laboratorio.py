# -*- coding: utf-8 -*-
"""
riproduci_laboratorio.py - Ricalcola dai dati grezzi i numeri dell'esperimento controllato (paragrafo 3.2).

Uso (dalla cartella analisi/):
    python riproduci_laboratorio.py ../dati/laboratorio

La cartella deve contenere i quattro file dell'esperimento, non modificati:
    manana_A_http.csv  manana_B_http.csv  server_log_test_A_http.csv  server_log_test_B_http.csv

Passi:
  1. Abbinamento. In ogni sessione le connessioni TCP di Manana verso il server (10.0.2.2) sono abbinate
     a quelle del registro del server, porta per porta, in ordine di apertura. I due registri sono
     scritti da orologi diversi: lo sfasamento (costante nella sessione) e' STIMATO dai dati, come mediana,
     sulle porte dedicate, di (prima apertura nel server - prima apertura in Manana). Non e' una misura.
  2. Riconciliazione dei byte:  S_M = S_srv + 60 + 40k   e   R_M = R_srv + 48 + 40k'   (k, k' interi >= 0).
  3. Connessioni con/senza richiesta secondo il server e secondo la soglia di 300 byte.
  4. Tabella 3.3 (profili per scenario) e Tabella 3.4 (firma per scenario, per navigazione).
  5. Connessioni non appartenenti agli scenari, e affidabilita' di stato e durata.
Alla fine un riquadro confronta i numeri principali con quelli riportati nella tesi.

Solo libreria standard. Il server legge la richiesta in base al contenuto (richiesta HTTP completa o
ClientHello completo entro 10 s), non in base ai byte: e' un criterio indipendente dalla soglia di Manana.
"""

import collections
import csv
import os
import statistics
import sys
from datetime import timedelta

import firma as F

IP_SERVER = "10.0.2.2"
FILE_SESSIONI = {
    "A": ("manana_A_http.csv", "server_log_test_A_http.csv"),
    "B": ("manana_B_http.csv", "server_log_test_B_http.csv"),
}
PORTE_TLS = {8443, 8444, 8445, 8446}
GAP_NAVIGAZIONE = 60.0       # s: una pausa maggiore inizia una nuova navigazione (porte senza numero di prova)


def leggi_server(percorso):
    righe = []
    with open(percorso, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            righe.append({
                "apertura": F.leggi_orario(r["ora_apertura"]), "scenario": r["scenario"], "path": r["path"],
                "rx": int(r["byte_ricevuti"]), "tx": int(r["byte_inviati"]), "chiusura": r["chiusura"],
                "durata": float(r["durata_s"]), "porta": int(r["porta_server"]), "prova": r["prova"]})
    return righe


def abbina(conn, server):
    """Abbina le connessioni di Manana a quelle del server. Restituisce (coppie, offset in s, note)."""
    per_porta_m, per_porta_s = collections.defaultdict(list), collections.defaultdict(list)
    for c in conn:
        per_porta_m[c["dstport"]].append(c)
    for s in server:
        per_porta_s[s["porta"]].append(s)
    dedicate = [p for p in per_porta_m if p != 8080]
    offset = statistics.median(
        (min(s["apertura"] for s in per_porta_s[p]) - min(c["inizio"] for c in per_porta_m[p])).total_seconds()
        for p in dedicate)
    note, coppie = [], []
    for porta in sorted(per_porta_m):
        m = sorted(per_porta_m[porta], key=lambda c: c["inizio"])
        s = sorted(per_porta_s[porta], key=lambda x: x["apertura"])
        if len(s) > len(m):   # righe del server precedenti all'avvio della cattura di Manana
            limite = m[0]["inizio"] + timedelta(seconds=offset) - timedelta(seconds=5)
            esclusi = [x for x in s if x["apertura"] < limite]
            s = [x for x in s if x["apertura"] >= limite]
            note.append(f"porta {porta}: escluse {len(esclusi)} righe del server precedenti all'avvio della cattura")
        if len(m) != len(s):
            raise SystemExit(f"Porta {porta}: {len(m)} connessioni in Manana e {len(s)} nel server: abbinamento impossibile")
        for c, x in zip(m, s):
            scarto = abs((x["apertura"] - c["inizio"]).total_seconds() - offset)
            coppie.append({"m": c, "s": x, "scarto": scarto})
    return coppie, offset, note


def migliore(etichette):
    for e in ("completa", "parziale", "assente"):
        if e in etichette:
            return e


def navigazioni(gruppo):
    """Assegna a ogni coppia una navigazione: numero di prova del server se c'e' (porte HTTP), altrimenti
    raggruppamento per tempo (pausa > 60 s)."""
    if all(p["s"]["prova"] not in ("-", "") for p in gruppo):
        return {id(p): p["s"]["prova"] for p in gruppo}
    ordine = sorted(gruppo, key=lambda p: p["m"]["inizio"])
    nav, precedente, risultato = 0, None, {}
    for p in ordine:
        if precedente is None or (p["m"]["inizio"] - precedente).total_seconds() > GAP_NAVIGAZIONE:
            nav += 1
        risultato[id(p)] = str(nav)
        precedente = p["m"]["inizio"]
    return risultato


def titolo(testo):
    print("\n" + testo + "\n" + "-" * len(testo))


def main(cartella):
    sessioni, tutte = {}, []
    for k, (fm, fs) in FILE_SESSIONI.items():
        pm, ps = os.path.join(cartella, fm), os.path.join(cartella, fs)
        for p in (pm, ps):
            if not os.path.exists(p):
                raise SystemExit(f"File non trovato: {p}")
        completo = F.leggi_manana(pm)                       # tutte le connessioni TCP (anche non verso il server)
        F.applica_firma(completo)
        lab = [c for c in completo if c["dstip"] == IP_SERVER]
        coppie, offset, note = abbina(lab, leggi_server(ps))
        for p in coppie:
            p["sessione"] = k
        sessioni[k] = {"completo": completo, "lab": lab, "coppie": coppie, "offset": offset, "note": note}
        tutte.extend(coppie)

    titolo("1. Abbinamento tra report di Manana e registro del server")
    for k, s in sessioni.items():
        per_porta = collections.Counter(c["dstport"] for c in s["lab"])
        sc = [p["scarto"] for p in s["coppie"]]
        print(f"Sessione {k}: connessioni abbinate {len(s['coppie'])} | sfasamento stimato {s['offset']:.1f} s | "
              f"scarto di apertura dopo la correzione: mediana {statistics.median(sc):.2f} s, max {max(sc):.2f} s")
        print("   connessioni per porta:", dict(sorted(per_porta.items())))
        for n in s["note"]:
            print("   nota:", n)
    print(f"Totale connessioni abbinate: {len(tutte)}")

    titolo("2. Riconciliazione dei byte  S_M = S_srv + 60 + 40k,  R_M = R_srv + 48 + 40k'")
    def k_valori(p):
        a, b = p["m"]["inviati"] - p["s"]["rx"] - 60, p["m"]["ricevuti"] - p["s"]["tx"] - 48
        return a, b, (a >= 0 and b >= 0 and a % 40 == 0 and b % 40 == 0)
    ok = [p for p in tutte if k_valori(p)[2]]
    eccezioni = collections.Counter(p["s"]["scenario"] for p in tutte if not k_valori(p)[2])
    print(f"Riconciliano: {len(ok)} su {len(tutte)} | eccezioni per scenario: {dict(eccezioni)}")
    n = [p for p in tutte if p["s"]["scenario"] == "NORMALE"]
    print("NORMALE: server riceve", sorted({p['s']['rx'] for p in n}), "e invia", sorted({p['s']['tx'] for p in n}),
          "| Manana registra inviati", sorted({p['m']['inviati'] for p in n}),
          "ricevuti", sorted({p['m']['ricevuti'] for p in n}))
    rp = [p for p in tutte if p["s"]["scenario"] == "RESET_PARZIALE"]
    print("RESET_PARZIALE: il server invia", sorted({p['s']['tx'] for p in rp}), "| ricevuti in Manana",
          dict(collections.Counter(p['m']['ricevuti'] for p in rp)))

    titolo("3. Connessioni con e senza richiesta")
    con = [p for p in tutte if p["m"]["inviati"] > F.SOGLIA_INVIATI]
    senza = [p for p in tutte if p["m"]["inviati"] <= F.SOGLIA_INVIATI]
    inc1 = sum(1 for p in con if p["s"]["scenario"] == "NESSUNA_RICHIESTA")
    inc2 = sum(1 for p in senza if p["s"]["scenario"] != "NESSUNA_RICHIESTA")
    print(f"Con richiesta (> {F.SOGLIA_INVIATI} byte inviati): {len(con)} | senza: {len(senza)}")
    print(f"Incoerenze con il registro del server (classifica per contenuto): {inc1} + {inc2}")
    print("Senza richiesta: profili inviati/ricevuti", dict(collections.Counter((p['m']['inviati'], p['m']['ricevuti']) for p in senza)),
          "| byte letti dal server", sorted({p['s']['rx'] for p in senza}),
          "| durata nel server", f"{min(p['s']['durata'] for p in senza):.2f}-{max(p['s']['durata'] for p in senza):.2f} s")
    max_senza = max(p["m"]["inviati"] for p in senza)
    min_con = min(p["m"]["inviati"] for p in con)
    max_int = max(p["m"]["ricevuti"] for p in con if p["m"]["ricevuti"] <= F.SOGLIA_RICEVUTI)
    min_risp = min(p["m"]["ricevuti"] for p in con if p["m"]["ricevuti"] > F.SOGLIA_RICEVUTI)
    print(f"Massimo inviato senza richiesta: {max_senza} | minimo con richiesta: {min_con} | "
          f"massimo ricevuto tra le candidate: {max_int} | minimo ricevuto con risposta: {min_risp}")

    titolo("4a. Tabella 3.3 - profili per scenario (solo connessioni con richiesta; esclusi favicon e pagina indice)")
    scenari = {}
    for p in con:
        if p["s"]["scenario"] in ("ALTRO", "INDICE"):
            continue
        scenari.setdefault((p["m"]["dstport"], p["s"]["scenario"]), []).append(p)
    nav_di = {}
    print(f"{'scenario':<16}{'porta':>6}{'nav':>5}{'conn':>6}  {'inviati':<12}{'ricevuti (n. conn.)':<34}conn/nav")
    for (porta, sc), g in sorted(scenari.items()):
        nav_di.update(navigazioni(g))
        per_nav = collections.Counter(nav_di[id(p)] for p in g)
        ric = dict(sorted(collections.Counter(p["m"]["ricevuti"] for p in g).items()))
        inv = sorted(p["m"]["inviati"] for p in g)
        print(f"{sc:<16}{porta:>6}{len(per_nav):>5}{len(g):>6}  {inv[0]}-{inv[-1]:<8}{str(ric):<34}{min(per_nav.values())}-{max(per_nav.values())}")

    titolo("4b. Tabella 3.4 - firma per scenario (ogni navigazione ha la migliore etichetta delle sue connessioni)")
    print(f"{'scenario':<16}{'nav':>4}{'conn':>6}{'cand':>6}{'completa':>10}{'parziale':>10}{'assente':>9}")
    tab34 = {}
    for (porta, sc), g in sorted(scenari.items()):
        per_nav = collections.defaultdict(list)
        for p in g:
            per_nav[nav_di[id(p)]].append(p["m"]["firma"])
        esiti = collections.Counter(migliore(v) for v in per_nav.values())
        cand = sum(1 for p in g if p["m"]["cand"])
        tab34[sc] = (len(per_nav), len(g), cand, esiti["completa"], esiti["parziale"], esiti["assente"])
        print(f"{sc:<16}{len(per_nav):>4}{len(g):>6}{cand:>6}{esiti['completa']:>10}{esiti['parziale']:>10}{esiti['assente']:>9}")
    completa_rp = [p for p in rp if p["m"]["firma"] == "completa"]
    if completa_rp:
        risp = [c for c in sessioni[completa_rp[0]["sessione"]]["completo"]
                if c["dstport"] == completa_rp[0]["m"]["dstport"] and c["risp"]]
        dist = [min(abs((c["inizio"] - p["m"]["inizio"]).total_seconds()) for c in risp) for p in completa_rp]
        print(f"RESET_PARZIALE: {len(completa_rp)} connessioni con firma completa (prova {completa_rp[0]['s']['prova']}); "
              f"distanza dalla connessione con risposta piu' vicina: {', '.join(f'{d:.0f}' for d in dist)} s "
              f"(minimo {min(dist):.0f} s, finestra {F.FINESTRA:.0f} s)")

    titolo("5a. Altre connessioni con richiesta (non appartenenti agli scenari)")
    indice = [p for p in con if p["m"]["dstport"] == 8080]
    altre_dest = [c for k in sessioni for c in sessioni[k]["completo"] if c["dstip"] != IP_SERVER and c["req"]]
    cand_altre = sum(1 for c in altre_dest if c["cand"])
    print(f"Verso la porta 8080 (pagina indice e favicon): {len(indice)} con richiesta, "
          f"minimo ricevuto {min(p['m']['ricevuti'] for p in indice)} byte, candidate {sum(1 for p in indice if p['m']['cand'])}")
    print(f"Verso altre destinazioni TCP: {len(altre_dest)} con richiesta, minimo ricevuto "
          f"{min(c['ricevuti'] for c in altre_dest)} byte, candidate {cand_altre}")

    titolo("5b. Affidabilita' di stato e durata")
    con_closed = [p for p in con if "Closed" in p["m"]["stati"]]
    multi = [p for p in tutte if p["m"]["righe"] > 1]
    print(f"Con richiesta e 'Closed' in almeno una riga: {len(con_closed)} (righe per connessione: "
          f"{dict(collections.Counter(p['m']['righe'] for p in con_closed))})")
    print(f"Connessioni presenti in piu' righe: {len(multi)} | di cui con 'Closed' in qualche riga: "
          f"{sum(1 for p in multi if 'Closed' in p['m']['stati'])}")
    lunghe = [p for p in tutte if (p["m"]["fine"] - p["m"]["inizio"]).total_seconds() >= 20]
    print(f"Durata nel report >= 20 s: {len(lunghe)} connessioni {dict(collections.Counter(p['s']['scenario'] for p in lunghe))}; "
          f"durata nel server: {sorted({round(p['s']['durata'], 1) for p in lunghe})} s")
    timeout = [p for p in tutte if p["s"]["scenario"] == "TIMEOUT"]
    print(f"TIMEOUT: durata nel report {min((p['m']['fine']-p['m']['inizio']).total_seconds() for p in timeout):.2f}-"
          f"{max((p['m']['fine']-p['m']['inizio']).total_seconds() for p in timeout):.2f} s "
          f"contro circa 15 s nel server")

    titolo("Confronto con i numeri della tesi")
    controlli = [
        ("connessioni abbinate", len(tutte), 349),
        ("riconciliano con la formula (1)", len(ok), 311),
        ("eccezioni TLS_NORMALE", eccezioni.get("TLS_NORMALE", 0), 27),
        ("eccezioni RESET_PARZIALE", eccezioni.get("RESET_PARZIALE", 0), 11),
        ("connessioni con richiesta", len(con), 254),
        ("connessioni senza richiesta", len(senza), 95),
        ("incoerenze con il server", inc1 + inc2, 0),
        ("max inviati senza richiesta", max_senza, 180),
        ("min inviati con richiesta", min_con, 550),
        ("max ricevuti tra le candidate", max_int, 168),
        ("min ricevuti con risposta", min_risp, 425),
        ("con richiesta verso 8080", len(indice), 47),
        ("con richiesta verso altre destinazioni", len(altre_dest), 31),
        ("candidate tra le non appartenenti agli scenari", cand_altre + sum(1 for p in indice if p["m"]["cand"]), 0),
        ("navigazioni RESET/TIMEOUT/TLS_RESET/TLS_TIMEOUT rilevate",
         sum(tab34[s][3] for s in ("RESET", "TIMEOUT", "TLS_RESET", "TLS_TIMEOUT")), 20),
        ("navigazioni FIN_VUOTO/TLS_FIN rilevate", sum(tab34[s][3] for s in ("FIN_VUOTO", "TLS_FIN")), 9),
        ("navigazioni attese negative: completa", sum(tab34[s][3] for s in ("NORMALE", "TLS_NORMALE", "RESET_PARZIALE")), 1),
        ("navigazioni attese negative: parziale", sum(tab34[s][4] for s in ("NORMALE", "TLS_NORMALE", "RESET_PARZIALE")), 4),
        ("navigazioni attese negative: assente", sum(tab34[s][5] for s in ("NORMALE", "TLS_NORMALE", "RESET_PARZIALE")), 10),
        ("durata >= 20 s nel report", len(lunghe), 7),
        ("connessioni con richiesta e 'Closed'", len(con_closed), 45),
        ("connessioni in piu' righe", len(multi), 301),
        ("... di cui con 'Closed'", sum(1 for p in multi if "Closed" in p["m"]["stati"]), 0),
    ]
    diversi = 0
    for nome, trovato, atteso in controlli:
        esito = "OK  " if trovato == atteso else "DIFF"
        diversi += trovato != atteso
        print(f"  [{esito}] {nome}: trovato {trovato}, tesi {atteso}")
    print("\nTutti i numeri coincidono con la tesi." if not diversi else f"\n{diversi} numeri differiscono dalla tesi.")
    return 0 if not diversi else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) != 2:
        raise SystemExit("Uso: python riproduci_laboratorio.py <cartella con i 4 CSV di laboratorio>")
    sys.exit(main(sys.argv[1]))
