# Analisi

Solo libreria standard di Python (3.8 o successivo). Lanciare gli script dalla cartella `analisi/`.

| File | Funzione |
|---|---|
| `firma.py` | Lettura dei report di Manana e applicazione della firma (libreria) |
| `applica_firma.py` | Applica la firma a uno o più report e stampa un riepilogo per destinazione |
| `riproduci_laboratorio.py` | Ricalcola i numeri dell'esperimento controllato e li confronta con la tesi |

## La firma

Per ogni connessione c, aggregate le righe del report: s(c) e r(c) sono i byte inviati e ricevuti, t(c) l'istante di
apertura, d(c) la destinazione (IP e porta). Con soglie σs = 300 byte, σr = 200 byte e finestra Δ = 120 s:

    req(c)   <=>  s(c) > σs                      con richiesta
    risp(c)  <=>  req(c) e r(c) > σr             con risposta
    cand(c)  <=>  req(c) e r(c) <= σr            candidata
    V(c)      =   { c' : d(c') = d(c) e |t(c') - t(c)| <= Δ }       connessioni vicine (c compresa)
    n_cand(c) =   numero di candidate in V(c)
    n_risp(c) =   numero di connessioni con risposta in V(c)

    firma(c) = completa   se cand(c) e n_cand(c) >= 2 e n_risp(c) = 0
               parziale   se cand(c), negli altri casi
               assente    se non cand(c)

Poiché c appartiene a V(c), la condizione n_cand(c) >= 2 richiede, oltre a c, almeno un'altra candidata in V(c).
La firma usa solo i byte e la ripetizione verso la stessa destinazione, non stato, durata o numero di pacchetti.

## Uso

    python riproduci_laboratorio.py ../dati/laboratorio
    python applica_firma.py report.csv
    python applica_firma.py report.csv --out connessioni.csv
    python applica_firma.py report.csv --solo-ip 10.0.2.2
    python applica_firma.py report.csv --tutte

`--out` scrive una riga per connessione con byte, req, risp, cand, n_cand, n_risp e firma. Le opzioni `--inviati`,
`--ricevuti` e `--finestra` cambiano soglie e finestra per prova; i risultati della tesi si ottengono con i valori
di default.

## Limiti

La firma segnala un pattern di interruzione dopo l'invio della richiesta, compatibile con un'interferenza sulla
connessione ma anche con la chiusura o il guasto della controparte. Non attribuisce una causa. Soglie e condizione
per destinazione sono state definite osservando le catture esplorative: i risultati sui dati di laboratorio sono un
controllo di coerenza, non una validazione indipendente.
