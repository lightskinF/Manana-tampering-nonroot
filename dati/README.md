# Dati

## laboratorio/

Esperimento controllato del paragrafo 3.2, in due sessioni con Manana in modalità non-root e Chrome come unica
applicazione verso il server.

| File | Contenuto |
|---|---|
| `manana_A_http.csv` | Report di Manana, sessione A (scenari HTTP, porte 8080-8085) |
| `manana_B_http.csv` | Report di Manana, sessione B (scenari TLS, porte 8443-8446, e pagina indice) |
| `server_log_test_A_http.csv` | Registro del server, sessione A |
| `server_log_test_B_http.csv` | Registro del server, sessione B |

I file sono quelli prodotti dagli strumenti, non modificati. Note per l'uso:

- Il report di Manana è un registro di istantanee: una connessione compare in più righe e i byte di ogni riga sono
  incrementi. I totali per connessione si ottengono sommando le righe con la stessa porta sorgente, lo stesso IP e la
  stessa porta di destinazione. Stato, durata e contatori di pacchetti non sono affidabili (paragrafo 3.2).
- I due registri sono scritti da orologi diversi (il PC per il server, l'emulatore per Manana). Lo sfasamento, diverso
  nelle due sessioni, è stimato dai dati e non misurato; `riproduci_laboratorio.py` lo sottrae prima dell'abbinamento.
- Lo scenario di una connessione si riconosce dalla porta di destinazione.
- Nel registro della sessione A ci sono tre righe sulla porta 8080 precedenti all'avvio della cattura di Manana:
  `riproduci_laboratorio.py` le esclude e lo segnala.
- Contenuto: traffico di Chrome verso il server di laboratorio (`10.0.2.2`) e traffico di sistema dell'emulatore
  (servizi Google, YouTube Music). Non compaiono altri siti o applicazioni.

## Catture reali

Le catture della fase esplorativa (paragrafo 3.3) non sono pubblicate: contengono il traffico completo del
dispositivo. Sono disponibili su richiesta.
