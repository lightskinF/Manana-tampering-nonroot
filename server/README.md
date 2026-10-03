# Server di riferimento

`server_controllato_esteso.py` è lo script usato per l'esperimento del paragrafo 3.2.
Richiede Python 3 e solo la libreria standard.

## Come funziona

Il server gira sullo stesso PC dell'emulatore Android, che lo raggiunge all'indirizzo `10.0.2.2` (l'alias con cui
l'emulatore designa il computer ospite). Il comportamento è deciso dalla porta a cui il client si connette, una
per scenario. Prima di agire, il server legge per intero la richiesta HTTP oppure il ClientHello TLS.

| Porta | Scenario | Comportamento dopo la lettura della richiesta |
|---|---|---|
| 8080 | indice | pagina con i collegamenti numerati usati per la raccolta |
| 8081 | NORMALE | risponde con una pagina HTML e chiude con FIN |
| 8082 | RESET | non risponde e chiude con RST (SO_LINGER a 0) |
| 8083 | TIMEOUT | non risponde, silenzio per 15 s, poi FIN |
| 8084 | FIN_VUOTO | non risponde e chiude subito con FIN |
| 8085 | RESET_PARZIALE | invia 625 byte, attende 0,3 s e chiude con RST |
| 8443 | TLS_RESET | legge il ClientHello e chiude con RST |
| 8444 | TLS_TIMEOUT | legge il ClientHello, silenzio per 15 s, poi FIN |
| 8445 | TLS_FIN | legge il ClientHello e chiude subito con FIN |
| 8446 | TLS_NORMALE | handshake TLS completo con certificato auto-firmato, poi risposta |

Una connessione è registrata come "con richiesta" se il server riceve, entro 10 s, una richiesta HTTP completa
(porte HTTP) o un ClientHello completo (porte TLS); altrimenti è `NESSUNA_RICHIESTA`. Il criterio dipende dal
contenuto e non dal numero di byte.

## Certificato (solo per lo scenario TLS_NORMALE)

La chiave privata non è nel repository. Per generare una coppia certificato/chiave auto-firmata, nella cartella
dello script:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=10.0.2.2"

Chrome mostrerà un avviso di certificato, perché è auto-firmato. Su Windows `openssl` è incluso in Git for Windows
(`C:\Program Files\Git\usr\bin\openssl.exe`).

## Esecuzione

    python server_controllato_esteso.py

Ogni connessione è stampata a schermo e aggiunta a `server_log.csv` nella cartella da cui si lancia lo script.
Se il file è aperto in Excel la scrittura fallisce: aprire sempre una copia. Su Windows il firewall potrebbe
chiedere di consentire a Python l'accesso alle reti private.
