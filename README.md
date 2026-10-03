# Manana in modalità non-root: esperimento con server di riferimento

Materiale di accompagnamento della tesi di Fabio Greco, Università degli Studi di Napoli Federico II, 2026.
Contiene il server di riferimento, i dati dell'esperimento controllato (Capitolo 3, paragrafo 3.2) e gli
script che ricalcolano i numeri riportati nella tesi.

## Che cosa contiene

| Cartella | Contenuto |
|---|---|
| `server/` | Script del server di riferimento: un comportamento TCP noto per ogni porta (risposta normale, reset, silenzio, chiusura con FIN, risposta parziale seguita da reset, scenari TLS) |
| `dati/laboratorio/` | Report di Manana e registri del server delle due sessioni (A: HTTP, B: TLS), come prodotti, non modificati |
| `analisi/` | Script che applicano la firma e ricalcolano le tabelle del paragrafo 3.2 |

## Riprodurre i numeri del paragrafo 3.2

Serve Python 3.8 o successivo (solo libreria standard). Dalla cartella `analisi/`:

    python riproduci_laboratorio.py ../dati/laboratorio

Lo script abbina le connessioni di Manana a quelle del server, verifica la riconciliazione dei byte, ricalcola le
Tabelle 3.3 e 3.4 e confronta i numeri con quelli della tesi (`OK` o `DIFF` per ciascuno).

## Applicare la firma a un altro report di Manana

    python applica_firma.py percorso/report.csv

Per ogni destinazione con connessioni candidate stampa i profili di byte e l'etichetta della firma. Opzioni e
definizione formale della regola in `analisi/README.md`.

## Eseguire il server

Istruzioni, scenari e generazione del certificato in `server/README.md`.

## Avvertenze

- Il dataset di laboratorio non rappresenta un caso di censura reale: gli scenari di interruzione sono controllati
  e servono a verificare la corrispondenza tra il comportamento noto del server e il traffico osservato da Manana.
- La firma segnala un pattern (richiesta senza risposta applicativa, ripetuta verso la stessa destinazione, senza
  successi vicini nel tempo). Non attribuisce una causa e non è una prova di censura. In modalità non-root un reset
  inviato dalla controparte e uno iniettato da un terzo non si distinguono.
- L'esperimento è locale e usa una sola combinazione di applicazione e dispositivo (Chrome nell'emulatore Android).
  Il riconoscimento degli scenari è un controllo di coerenza, non una misura della capacità di rilevamento.
- Le catture reali della fase esplorativa non sono pubblicate, perché contengono il traffico completo del
  dispositivo. Sono disponibili su richiesta; la firma può essere applicata a catture proprie con `applica_firma.py`.

## Versione citata nella tesi

Tag `v1.0-tesi`.

## Licenza

Codice: MIT (file `LICENSE`).
