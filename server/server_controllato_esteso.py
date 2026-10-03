#!/usr/bin/env python3
"""
server_controllato_esteso.py - Server di test per l'esperimento del Capitolo 3
(versione estesa di server_controllato.py).

Produce comportamenti TCP noti ("ground truth") da confrontare con quello
che registra Manana. Il comportamento e' deciso dalla PORTA a cui si
connette l'emulatore: cosi' nel report di Manana la porta di destinazione
(DstPort) dice gia' quale scenario e' in corso, senza dover allineare gli
orari con il log del server (utile se l'orologio dell'emulatore e' sfasato).
Ogni scenario e' quindi anche una "destinazione" distinta.

  HTTP - la richiesta viene letta per intero, poi:
    8081  NORMALE         risponde con una pagina HTML e chiude in modo pulito (FIN)
    8082  RESET           non risponde e abbatte la connessione con un RST
    8083  TIMEOUT         non risponde e resta in silenzio per DURATA_TIMEOUT
                          secondi, poi chiude in modo pulito (FIN)
    8084  FIN_VUOTO       non risponde e chiude subito con un FIN
    8085  RESET_PARZIALE  invia l'inizio di una risposta, poi abbatte con un RST
    8080  (porta "mista") lo scenario si sceglie dal path, come nella versione
                          precedente: /normale  /reset  /timeout  /fin  /parziale
                          (il path "/" mostra una pagina indice con i link)

  TLS - non c'e' HTTP: il server legge il ClientHello (il primo messaggio
  TLS del client) e poi agisce. Servono per il caso "ClientHello -> RST":
    8443  TLS_RESET       ClientHello -> RST
    8444  TLS_TIMEOUT      ClientHello -> silenzio per DURATA_TIMEOUT s -> FIN
    8445  TLS_FIN          ClientHello -> FIN subito, senza risposta
    8446  TLS_NORMALE      handshake TLS vero (servono cert.pem e key.pem
                           accanto a questo file; il certificato e' auto-firmato,
                           quindi Chrome mostra un avviso)

Il path /favicon.ico (che il browser chiede da solo) riceve sempre un 404 ed
e' registrato come ALTRO, cosi' non si confonde con gli scenari. Qualsiasi
URL accetta una query per numerare le prove, ad esempio /reset?prova=3: lo
scenario non cambia e nel log il numero compare nella colonna "prova".
Sulle porte HTTP, ?s=N cambia i secondi di silenzio dello scenario TIMEOUT
(es. /?s=5 sulla 8083, oppure /timeout?s=5 sulla 8080).

Ogni connessione viene stampata a schermo e aggiunta a server_log.csv
(nella cartella da cui si lancia lo script). Gli orari sono in UTC.
Le prime 10 colonne del log sono le stesse della versione precedente; in
fondo sono state aggiunte porta_server, prova e sni.

Lo STESSO file si usa in entrambe le fasi dell'esperimento:
  Fase 1 - PC Windows, in locale:   python server_controllato_esteso.py
           dall'emulatore:          http://10.0.2.2:8080/   (pagina indice con i link)
  Fase 2 - VPS Linux:               python3 server_controllato_esteso.py
           dall'emulatore:          http://IP_DELLA_VPS:8080/
           (sulla VPS vanno aperte le porte 8080-8085 e 8443-8446 del firewall)
"""
#in realtà la fase 2 serve per il paragrafo inerente a SVILUPPI FUTURI, per ora mi sono limitato alla fase 1 in locale.

import csv
import datetime
import os
import socket
import ssl
import struct
import threading
import time
from urllib.parse import parse_qs

# ---------------------------------------------------------------------
# CONFIGURAZIONE (se serve cambiare qualcosa, si cambia solo qui)
# ---------------------------------------------------------------------
HOST = "0.0.0.0"          # ascolta su tutte le interfacce di rete
PORTA = 8080              # porta "mista": lo scenario si sceglie dal path; su questa porta c'è la pagina indice con i link numerati per ogni scenario
DURATA_TIMEOUT = 15      # secondi di silenzio nello scenario /timeout, possiamo modificarlo a piacere, per ora numero piccolo x testare, poi aumento un po'...
DURATA_MASSIMA = 120      # limite superiore accettato per ?s=N
ATTESA_RICHIESTA = 10     # secondi massimi per ricevere la richiesta HTTP (o il ClientHello TLS)
BYTE_PARZIALI = 500       # RESET_PARZIALE: byte di corpo inviati prima del RST
BYTE_DICHIARATI = 4000    # RESET_PARZIALE: Content-Length annunciato (maggiore di quanto inviato)
PAUSA_PRIMA_RST = 0.3     # secondi tra l'invio parziale e il RST: il RST con SO_LINGER 0 butta via i dati non ancora partiti, quindi si aspetta che escano
N_LINK = 5                # quanti link numerati per scenario nella pagina indice
FILE_LOG = "server_log.csv"
# Certificato e chiave si cercano accanto allo script, da qualunque cartella lo si lanci.
CARTELLA_SCRIPT = os.path.dirname(os.path.abspath(__file__))
FILE_CERT = os.path.join(CARTELLA_SCRIPT, "cert.pem")
FILE_CHIAVE = os.path.join(CARTELLA_SCRIPT, "key.pem")

# porta -> (tipo, scenario fisso). Se lo scenario fisso e' None la porta e' "mista"
# e lo scenario si sceglie dal path (vedi SCENARI_PER_PATH).
PORTE = {
    PORTA: ("HTTP", None),
    8081: ("HTTP", "NORMALE"),
    8082: ("HTTP", "RESET"),
    8083: ("HTTP", "TIMEOUT"),
    8084: ("HTTP", "FIN_VUOTO"),
    8085: ("HTTP", "RESET_PARZIALE"),
    8443: ("TLS", "TLS_RESET"),
    8444: ("TLS", "TLS_TIMEOUT"),
    8445: ("TLS", "TLS_FIN"),
    8446: ("TLS", "TLS_NORMALE"),
}

# Solo per la porta mista: path -> scenario.
SCENARI_PER_PATH = {
    "/": "INDICE",
    "/normale": "NORMALE",
    "/reset": "RESET",
    "/timeout": "TIMEOUT",
    "/fin": "FIN_VUOTO",
    "/parziale": "RESET_PARZIALE",
}

COLONNE_LOG = [
    "ora_apertura", "ora_chiusura", "ip_client", "porta_client",
    "scenario", "path", "byte_ricevuti", "byte_inviati",
    "chiusura", "durata_s",
    "porta_server", "prova", "sni",
]

PAGINA_NORMALE = ("<html><body><h1>Scenario NORMALE</h1>"
                  "<p>Risposta regolare, chiusura con FIN.</p></body></html>")
PAGINA_404 = ("<html><body><h1>404</h1>"
              "<p>Path non previsto: apri la pagina indice (path /).</p></body></html>")

# Un solo lock condiviso: un thread alla volta scrive sul log, in maniera mutamente esclusiva.
lock_log = threading.Lock()

# Contesto TLS per lo scenario TLS_NORMALE: lo crea prepara_tls_normale()
# all'avvio, se trova cert.pem e key.pem.
CONTESTO_TLS = None


def ora_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def scrivi_log(riga):
    """Aggiunge una riga (un dizionario) al CSV e la stampa a schermo."""
    with lock_log:
        # Il controllo va fatto PRIMA di open(): la modalita' "a" crea il
        # file, quindi dopo l'apertura esisterebbe sempre.
        file_nuovo = not os.path.exists(FILE_LOG)
        try:
            with open(FILE_LOG, "a", newline="", encoding="utf-8") as f:        #da ACP ricorda: con with si chiude in automatico elegantemente; vale anche x il lock sopra
                writer = csv.DictWriter(f, fieldnames=COLONNE_LOG)
                if file_nuovo:
                    writer.writeheader()
                writer.writerow(riga)
        except PermissionError:
            # Su Windows, se il CSV e' aperto in Excel la scrittura e' vietata.
            # Il thread non deve morire: la riga resta almeno a schermo.
            print(f"!! ATTENZIONE: {FILE_LOG} e' aperto in un altro programma, riga NON scritta nel file. "
                  "Chiudilo (meglio: apri sempre una COPIA del log).")
        print(f"{riga['ora_chiusura']} | {riga['ip_client']}:{riga['porta_client']} -> :{riga['porta_server']} | "     #stampo valori filtrando il dizionario tramite keys
              f"{riga['scenario']} | {riga['path']} | chiusura: {riga['chiusura']} | "
              f"{riga['durata_s']} s")


def registra(apertura, ip, porta, porta_server, scenario, path,
             byte_ricevuti, byte_inviati, chiusura, prova="-", sni="-"):
    """Costruisce la riga del log (con l'orario di chiusura = adesso) e la scrive."""
    chiusura_ora = ora_utc()
    scrivi_log({
        "ora_apertura": apertura.isoformat(),
        "ora_chiusura": chiusura_ora.isoformat(),
        "ip_client": ip,
        "porta_client": porta,
        "scenario": scenario,
        "path": path,
        "byte_ricevuti": byte_ricevuti,
        "byte_inviati": byte_inviati,
        "chiusura": chiusura,
        "durata_s": f"{(chiusura_ora - apertura).total_seconds():.3f}",
        "porta_server": porta_server,
        "prova": prova,
        "sni": sni,
    })


def prepara_file_log():
    """Se esiste gia' un server_log.csv con colonne diverse (quello della
    versione precedente, con 10 colonne), lo rinomina: aggiungere righe con
    13 colonne sotto un'intestazione a 10 darebbe un file illeggibile."""
    if not os.path.exists(FILE_LOG):
        return
    with open(FILE_LOG, newline="", encoding="utf-8") as f:
        intestazione = next(csv.reader(f), [])
    if intestazione != COLONNE_LOG:
        nuovo_nome = f"server_log_precedente_{ora_utc():%Y%m%d_%H%M%S}.csv"
        try:
            os.rename(FILE_LOG, nuovo_nome)
        except OSError:
            raise SystemExit(f"{FILE_LOG} ha un formato vecchio e non riesco a rinominarlo "
                             "(e' aperto in Excel?). Chiudilo o spostalo e rilancia.")
        print(f"Trovato un {FILE_LOG} con formato precedente: rinominato in {nuovo_nome}")


def prepara_tls_normale():
    """Carica certificato e chiave per lo scenario TLS_NORMALE. Se mancano,
    quello scenario viene disattivato (gli altri non ne hanno bisogno)."""
    global CONTESTO_TLS
    try:
        contesto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contesto.load_cert_chain(FILE_CERT, FILE_CHIAVE)
        CONTESTO_TLS = contesto
    except (OSError, ssl.SSLError) as e:
        print(f"TLS_NORMALE disattivato ({e}): servono cert.pem e key.pem accanto allo script.")
        for porta, (tipo, scenario) in list(PORTE.items()):
            if scenario == "TLS_NORMALE":
                del PORTE[porta]


def leggi_richiesta(conn):  #gli passo la socket
    """Legge la richiesta HTTP fino alla riga vuota che chiude gli header
    (i byte \\r\\n\\r\\n). Leggerla tutta e' importante: se chiudessimo il
    socket lasciando dati non letti, il sistema operativo invierebbe un RST
    anche nello scenario normale.

    Restituisce (byte_letti, path), oppure (byte_letti, None) se entro
    ATTESA_RICHIESTA secondi non arriva una richiesta HTTP completa."""
    conn.settimeout(ATTESA_RICHIESTA)
    dati = b""          #tipo bytes, non str: la richiesta HTTP e' binaria; non lo conoscevo in python, ma poi utilizzo sempre decode e encode sui bytes per trasformarli in str e viceversa
    try:
        while b"\r\n\r\n" not in dati:
            pezzo = conn.recv(1024)
            if not pezzo:            # il client ha chiuso prima di finire
                break   #esco dal while, non ho ricevuto la richiesta completa
            dati += pezzo
            if len(dati) > 8192:     # troppo lunga per essere una richiesta normale
                break
    except OSError:
        # timeout scaduto (ATTESA_RICHIESTA secondi), oppure reset da parte del client:
        # teniamo quello che e' arrivato finora
        pass

    # Una richiesta valida inizia con una riga come: "GET /reset HTTP/1.1"
    prima_riga = dati.split(b"\r\n")[0].decode("ascii", errors="replace")   #splitto i dati ricevuti in righe sul carattere \r\n (prendo tutta la richiesta http); prendo la prima e la decodifico in ascii (se ci sono caratteri non validi li sostituisco con '?')
    parti = prima_riga.split()  #splitto la prima riga in parole separate da spazi, es. ['GET', '/reset', 'HTTP/1.1']; è una lista di stringhe ottenuta splittando sul carattere di default (spazio)
    if b"\r\n\r\n" in dati and len(parti) == 3 and parti[2].startswith("HTTP/"):
        return len(dati), parti[1]
    return len(dati), None


def leggi_client_hello(conn, consuma):
    """Legge il primo record TLS, cioe' il ClientHello. Un record TLS ha 5
    byte di intestazione: tipo (0x16 = handshake), versione (2 byte) e
    lunghezza del resto (2 byte). Si legge finche' il record e' completo:
    il ClientHello di Chrome e' lungo (oltre 1 KB) e puo' arrivare spezzato
    in piu' segmenti TCP.

    consuma=True : i byte vengono letti (e tolti dal socket). Serve negli
                   scenari in cui poi si chiude: chiudere con dati non letti
                   farebbe partire un RST al posto del FIN.
    consuma=False: i byte vengono solo "sbirciati" (MSG_PEEK) e restano nel
                   socket, perche' li deve rileggere il modulo ssl per fare
                   l'handshake vero (TLS_NORMALE).

    Restituisce (byte_letti, completo): completo e' False se non e' arrivato
    un ClientHello intero (client che chiude, silenzio oltre ATTESA_RICHIESTA
    secondi, oppure dati che non sono TLS)."""
    conn.settimeout(ATTESA_RICHIESTA)
    scadenza = time.monotonic() + ATTESA_RICHIESTA
    dati = b""
    while time.monotonic() < scadenza:
        try:
            if consuma:
                pezzo = conn.recv(4096)
                if not pezzo:            # il client ha chiuso prima di finire
                    break
                dati += pezzo
            else:
                # il peek restituisce SEMPRE tutto cio' che e' nel buffer, dall'inizio
                pezzo = conn.recv(16389, socket.MSG_PEEK)     # 5 + 16384 = record TLS piu' grande possibile
                if not pezzo:
                    break
                dati = pezzo
        except OSError:
            break                        # timeout o reset del client
        if len(dati) >= 5:
            if dati[0] != 0x16:          # non e' un handshake TLS
                return dati, False
            if len(dati) >= 5 + int.from_bytes(dati[3:5], "big"):
                return dati, True
        if not consuma:
            time.sleep(0.05)             # il peek non blocca se c'e' gia' qualcosa: evitiamo di girare a vuoto
    return dati, False


def estrai_sni(dati):
    """Estrae il nome del server (estensione SNI) dal ClientHello, solo per
    il log. Restituisce "-" se manca (accadra' sempre con un indirizzo IP
    nell'URL: Chrome non manda lo SNI per gli IP) o se non si riesce a leggerlo."""
    try:
        i = 5 + 4 + 2 + 32                # record(5) + intestazione handshake(4) + versione(2) + random(32)
        i += 1 + dati[i]                  # session id (lunghezza su 1 byte)
        i += 2 + int.from_bytes(dati[i:i + 2], "big")     # cipher suites (lunghezza su 2 byte)
        i += 1 + dati[i]                  # metodi di compressione
        fine_estensioni = i + 2 + int.from_bytes(dati[i:i + 2], "big")
        i += 2
        while i + 4 <= fine_estensioni:
            tipo = int.from_bytes(dati[i:i + 2], "big")
            lunghezza = int.from_bytes(dati[i + 2:i + 4], "big")
            if tipo == 0:                 # 0 = server_name
                # dati dell'estensione: lunghezza lista(2) tipo nome(1) lunghezza nome(2) nome
                n = int.from_bytes(dati[i + 7:i + 9], "big")
                return dati[i + 9:i + 9 + n].decode("ascii", errors="replace") or "-"
            i += 4 + lunghezza
    except IndexError:
        pass
    return "-"


def durata_da_query(query):
    """Legge ?s=N dalla query (secondi di silenzio dello scenario TIMEOUT).
    Se manca o non e' valido, vale DURATA_TIMEOUT. Il minimo e' 0.1: con
    settimeout(0) il socket diventerebbe non bloccante."""
    try:
        durata = float(query.get("s", [DURATA_TIMEOUT])[0])
    except ValueError:
        return DURATA_TIMEOUT
    if not 0 <= durata <= DURATA_MASSIMA:     # vale anche per nan e inf
        return DURATA_TIMEOUT
    return max(durata, 0.1)


def pagina_indice():
    """Pagina con un link numerato per ogni prova di ogni scenario, cosi' sull'emulatore
    basta un tocco per fare una navigazione (niente URL da digitare). L'host dei link
    si ricava dal browser (location.hostname), quindi funziona uguale in locale e sulla VPS."""
    righe = ""
    for porta in sorted(PORTE):
        tipo, scenario = PORTE[porta]
        if scenario is None:
            continue
        schema = "https" if tipo == "TLS" else "http"
        link = "".join(f'<a data-s="{schema}" data-p="{porta}" data-n="{n}">{n}</a>'
                       for n in range(1, N_LINK + 1))
        righe += f"<p><b>{scenario}</b> <small>(porta {porta})</small><br>{link}</p>"
    return (
        '<html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<style>body{font-family:sans-serif;margin:12px}p{margin:10px 0}"
        "a{display:inline-block;min-width:2.2em;text-align:center;padding:10px;margin:3px 3px 3px 0;"
        "border:1px solid #888;border-radius:6px;text-decoration:none}</style></head><body>"
        "<h2>Server controllato</h2>"
        "<p>Un tocco = una navigazione. Non ricaricare la pagina.</p>"
        f"{righe}"
        "<p>Porta mista (scenario nel path): "
        '<a href="/normale">/normale</a><a href="/reset">/reset</a><a href="/timeout">/timeout</a>'
        '<a href="/fin">/fin</a><a href="/parziale">/parziale</a></p>'
        "<script>document.querySelectorAll('a[data-p]').forEach(function(a){"
        "a.href=a.dataset.s+'://'+location.hostname+':'+a.dataset.p+'/?prova='+a.dataset.n;});"
        "</script></body></html>"
    )


def invia_risposta(conn, stato, pagina):
    """Invia una risposta HTTP completa e chiude normalmente (FIN).
    Restituisce (byte_inviati, chiusura): se il client ha gia' chiuso o
    resettato la connessione, l'invio fallisce e lo annotiamo nel log
    invece di far morire il thread (e perdere la riga)."""
    corpo = pagina.encode("utf-8")  #corpo pagina HTML ma da inviare ovviamente in binario
    header = (
        f"HTTP/1.1 {stato}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(corpo)}\r\n"
        "Cache-Control: no-store\r\n"   # il browser non deve usare una copia in cache
        "Connection: close\r\n"         # una connessione per ogni richiesta
        "\r\n"
    ).encode("utf-8")   #sempre in binario
    try:
        conn.sendall(header + corpo)
        byte_inviati = len(header) + len(corpo)
        chiusura = "FIN"
    except OSError:
        # Il client se n'e' andato prima di ricevere la risposta
        # (es. il browser ha annullato la richiesta).
        byte_inviati = 0
        chiusura = "il client ha chiuso prima della risposta"
    conn.close()                        # chiusura ordinata: parte un FIN
    return byte_inviati, chiusura


def invia_risposta_parziale(conn):
    """Scenario RESET_PARZIALE: annuncia una pagina lunga BYTE_DICHIARATI byte
    (Content-Length) ma ne manda solo BYTE_PARZIALI, poi abbatte la connessione
    con un RST. A differenza di RESET, qui il client ha GIA' ricevuto dati
    applicativi: serve come caso negativo "difficile", un RST che pero' non e'
    un RST senza risposta.
    Restituisce (byte_inviati, chiusura)."""
    corpo = ("<html><body>" + "x" * BYTE_PARZIALI)[:BYTE_PARZIALI].encode("utf-8")
    header = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {BYTE_DICHIARATI}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    try:
        conn.sendall(header + corpo)
    except OSError:
        conn.close()
        return 0, "il client ha chiuso prima della risposta"
    # Il RST sta fuori dal try: se chiudi_con_rst fallisse vogliamo vedere l'errore.
    time.sleep(PAUSA_PRIMA_RST)
    chiudi_con_rst(conn)
    return len(header) + len(corpo), "RST dopo risposta parziale"


def chiudi_con_rst(conn):
    """Abbatte la connessione con un RST invece del normale FIN.

    Si attiva l'opzione SO_LINGER con tempo di attesa 0: alla close() il
    sistema operativo non chiude in modo ordinato ma scarta la connessione
    e invia un RST. L'opzione vuole i byte di una struct C 'linger' con due
    campi (attiva, secondi), che su Windows e su Linux ha tipi diversi."""
    if os.name == "nt":                    # Windows: due unsigned short
        linger = struct.pack("HH", 1, 0)
    else:                                  # Linux (la VPS): due int
        linger = struct.pack("ii", 1, 0)   #questo mi serve per creare la struct C 'linger' con due campi (attiva, secondi) che su Windows e Linux ha TIPI DIVERSI
    # Nessun try/except: se l'opzione non si potesse impostare vogliamo un
    # errore visibile, non una chiusura FIN silenziosa che falserebbe i dati.
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    conn.close()


def resta_in_silenzio(conn, durata=None):
    """Scenario TIMEOUT: nessuna risposta, la connessione resta aperta e muta
    (come se il traffico venisse scartato). Dopo 'durata' secondi (di default
    DURATA_TIMEOUT) il server chiude con FIN. Se il client si stanca prima e
    chiude lui, lo annota. Restituisce la descrizione di come e' finita."""
    if durata is None:
        durata = DURATA_TIMEOUT
    conn.settimeout(durata)
    try:
        dati = conn.recv(1024)     # aspetta: qui il client non dovrebbe mandare nulla
        if dati == b"":
            esito = "il client ha chiuso prima (FIN)"
        else:
            esito = "il client ha inviato altri dati"
    except socket.timeout:
        esito = f"FIN dopo {durata:g}s di silenzio"
    except ConnectionError:
        esito = "il client ha chiuso prima (RST)"
    conn.close()
    return esito


def servi_tls_normale(conn):
    """Scenario TLS_NORMALE: handshake TLS vero con il certificato di prova, poi
    una normale risposta HTTP dentro il tunnel. Con il certificato auto-firmato
    Chrome interrompe di solito il primo handshake (avviso di sicurezza): anche
    quello e' un caso utile, perche' il server ha comunque inviato ServerHello e
    certificato. Dopo "Avanzate > Procedi" le richieste arrivano fino in fondo.

    Restituisce (byte_richiesta, byte_inviati, path, chiusura). I byte sono
    quelli applicativi, in chiaro, non quelli che passano sul filo."""
    try:
        conn_tls = CONTESTO_TLS.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as e:
        # wrap_socket chiude da solo il socket quando l'handshake fallisce
        motivo = getattr(e, "reason", None) or e.__class__.__name__
        return 0, 0, "-", f"handshake TLS non completato ({motivo})"
    byte_richiesta, path = leggi_richiesta(conn_tls)
    if path is None:
        conn_tls.close()
        return byte_richiesta, 0, "-", "handshake TLS completato ma nessuna richiesta HTTP"
    byte_inviati, chiusura = invia_risposta(conn_tls, "200 OK", PAGINA_NORMALE)
    return byte_richiesta, byte_inviati, path, chiusura


def gestisci_client_tls(conn, ip, porta, apertura, porta_server, scenario_porta):
    """Gestione di una connessione sulle porte TLS: si legge il ClientHello e
    poi si applica lo scenario della porta."""
    consuma = scenario_porta != "TLS_NORMALE"     # per l'handshake vero i byte devono restare nel socket
    hello, completo = leggi_client_hello(conn, consuma)
    byte_ricevuti = len(hello)
    byte_inviati = 0
    path = "-"
    sni = "-"

    if not completo:
        # Connessione aperta senza un ClientHello (connessione di riserva del browser,
        # oppure qualcuno che parla in chiaro su una porta TLS). Non e' uno scenario.
        scenario = "NESSUN_CLIENTHELLO"
        conn.close()
        chiusura = "chiusa senza ClientHello"
    else:
        scenario = scenario_porta
        sni = estrai_sni(hello)
        if scenario == "TLS_RESET":
            chiudi_con_rst(conn)
            chiusura = "RST dopo ClientHello"
        elif scenario == "TLS_TIMEOUT":
            chiusura = resta_in_silenzio(conn)
        elif scenario == "TLS_FIN":
            conn.close()                # il ClientHello e' stato letto tutto: parte un FIN, non un RST
            chiusura = "FIN subito dopo ClientHello"
        else:                           # TLS_NORMALE
            byte_richiesta, byte_inviati, path, chiusura = servi_tls_normale(conn)
            byte_ricevuti += byte_richiesta

    registra(apertura, ip, porta, porta_server, scenario, path,
             byte_ricevuti, byte_inviati, chiusura, sni=sni)


def gestisci_client(conn, indirizzo, porta_server):   #gli passo la socket aperta nella funzione main e l'indirizzo del client (IP, porta); in piu' la porta del server su cui e' arrivata la connessione
    """Eseguita in un thread per ogni connessione accettata. SERVER multi-threaded: ogni client e' gestito in parallelo, senza bloccare gli altri."""
    ip, porta = indirizzo[0], indirizzo[1]
    apertura = ora_utc()
    tipo, scenario_fisso = PORTE[porta_server]
    if tipo == "TLS":
        gestisci_client_tls(conn, ip, porta, apertura, porta_server, scenario_fisso)
        return

    byte_ricevuti, path = leggi_richiesta(conn)
    byte_inviati = 0
    prova = "-"

    if path is None:
        # Connessione aperta senza una richiesta HTTP: capita, ad esempio,
        # quando il browser apre connessioni "di riserva". Non e' uno scenario.
        scenario = "NESSUNA_RICHIESTA"
        conn.close()
        chiusura = "chiusa senza risposta"
    else:
        base, _, stringa_query = path.partition("?")     # "/reset?prova=3" -> "/reset", "?", "prova=3"
        query = parse_qs(stringa_query)                  # {"prova": ["3"]}
        prova = query.get("prova", ["-"])[0]
        if base == "/favicon.ico":
            nome = None                                  # richiesta automatica del browser: sempre ALTRO
        elif scenario_fisso is not None:
            nome = scenario_fisso                        # porta dedicata: lo scenario e' quello della porta
        else:
            nome = SCENARI_PER_PATH.get(base)            # porta mista: lo scenario si legge dal path
        if nome == "NORMALE":
            scenario = "NORMALE"
            byte_inviati, chiusura = invia_risposta(conn, "200 OK", PAGINA_NORMALE)
        elif nome == "INDICE":
            scenario = "INDICE"
            byte_inviati, chiusura = invia_risposta(conn, "200 OK", pagina_indice())
        elif nome == "RESET":
            scenario = "RESET"
            chiudi_con_rst(conn)
            chiusura = "RST"
        elif nome == "TIMEOUT":
            scenario = "TIMEOUT"
            chiusura = resta_in_silenzio(conn, durata_da_query(query))
        elif nome == "FIN_VUOTO":
            scenario = "FIN_VUOTO"
            conn.close()                # la richiesta e' stata letta tutta: parte un FIN, non un RST
            chiusura = "FIN subito, senza risposta"
        elif nome == "RESET_PARZIALE":
            scenario = "RESET_PARZIALE"
            byte_inviati, chiusura = invia_risposta_parziale(conn)
        else:
            scenario = "ALTRO"
            byte_inviati, chiusura = invia_risposta(conn, "404 Not Found", PAGINA_404)

    registra(apertura, ip, porta, porta_server, scenario,
             path if path is not None else "-",
             byte_ricevuti, byte_inviati, chiusura, prova=prova)


def crea_socket_ascolto(porta):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name != "nt":
        # Linux: permette di riavviare subito il server dopo Ctrl+C.
        # Su Windows NON va usato: li' permetterebbe a due server
        # di ascoltare sulla stessa porta nello stesso momento.
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, porta))
    srv.listen()
    # accept() con timeout di 1 secondo: su Windows un accept() bloccante
    # non si lascia interrompere da Ctrl+C.
    srv.settimeout(1.0)
    return srv


def ciclo_accept(srv, porta_server):
    """Accetta le connessioni su una porta e lancia un thread per ciascuna."""
    while True:     # ciclo infinito: il server resta in ascolto finché non riceve Ctrl+C
        try:
            conn, indirizzo = srv.accept()
        except socket.timeout:
            # Nessuna connessione in questo secondo: si riprova.
            # Qui NON si usa 'continue': un Ctrl+C premuto proprio su
            # quella riga sfuggiva all'except KeyboardInterrupt in main().
            pass
        except OSError:
            return      # il socket e' stato chiuso (arresto del server)
        else:
            # Il blocco 'else' di un try viene eseguito solo se accept()
            # NON ha sollevato eccezioni, cioe' se e' arrivato un client.
            t = threading.Thread(target=gestisci_client, args=(conn, indirizzo, porta_server), daemon=True)
            t.start()


def main():
    prepara_file_log()
    prepara_tls_normale()
    ascolti = {porta: crea_socket_ascolto(porta) for porta in PORTE}

    print(f"Ora UTC del PC all'avvio: {ora_utc():%Y-%m-%d %H:%M:%S}")
    print("Server in ascolto (porta -> scenario):")
    for porta, (tipo, scenario) in PORTE.items():
        print(f"  {porta}  {scenario or 'mista: scenario dal path (/normale /reset /timeout /fin /parziale, / = indice)'}")
    print(f"Silenzio di TIMEOUT / TLS_TIMEOUT: {DURATA_TIMEOUT}s, poi FIN")
    print(f"Log in: {os.path.abspath(FILE_LOG)}")
    print("Ctrl+C per fermare.\n")

    # Le porte dedicate hanno ciascuna il proprio ciclo in un thread di sfondo;
    # la porta mista resta nel thread principale, che e' quello che riceve il Ctrl+C.
    for porta, srv in ascolti.items():
        if porta != PORTA:
            threading.Thread(target=ciclo_accept, args=(srv, porta), daemon=True).start()
    try:
        ciclo_accept(ascolti[PORTA], PORTA)
    except KeyboardInterrupt:   #l'utente ha premuto Ctrl+C
        print("\nServer fermato.")
    finally:
        for srv in ascolti.values():
            srv.close()


if __name__ == "__main__":
    main()
