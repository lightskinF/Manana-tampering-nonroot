# Catture reali

Catture del paragrafo 3.3 (applicazione della firma a due blocchi reali), esportate da Manana in modalità non-root.

| File | Contenuto |
|---|---|
| `TIM_womenonweb_womenhelp.csv` | Telefono Android, linea domestica TIM, Chrome. womenonweb.org e womenhelp.org si aprono. |
| `Iliad_womenonweb_womenhelp.csv` | Stesso telefono, hotspot di un iPhone su rete mobile Iliad. Blocco sul DNS: nessuna connessione TCP verso i due domini. |
| `Turchia_VPN_womenonweb.csv` | Emulatore Android, Chrome, VPN sull'host con uscita in Turchia. Interruzione dopo il ClientHello verso womenonweb.org. |

Per riprodurre i risultati della Tabella 3.5 e della Tabella 3.6:

```
python analisi/applica_firma.py dati/catture_reali/TIM_womenonweb_womenhelp.csv      # 63 TCP, 58 con richiesta, 0 candidate
python analisi/applica_firma.py dati/catture_reali/Iliad_womenonweb_womenhelp.csv    # 33 TCP, 29 con richiesta, 0 candidate
python analisi/applica_firma.py dati/catture_reali/Turchia_VPN_womenonweb.csv        # 43 TCP, 40 con richiesta, 12 candidate (completa)
```

Le catture sono state ridotte in un solo punto: le righe relative a due siti non pertinenti allo studio (un servizio
di posta web e un secondo sito aperti in background dal browser) hanno nome di dominio, indirizzo IP, AS e paese
sostituiti da segnaposto (`[omesso]`, `192.0.2.1`, `Omesso`). Il numero di righe, i byte e le porte non cambiano,
e l'esito della firma è identico a quello ottenuto sui file originali. Il resto del contenuto è quello esportato da Manana:
l'IP sorgente è l'indirizzo virtuale della VPN locale, i nomi di dominio sono quelli visitati dal browser, e non sono
registrati URL, percorsi, cookie o contenuti delle pagine.

Come per i dati di laboratorio, il report è un registro di istantanee: i totali per connessione si ottengono sommando
le righe con la stessa porta sorgente, lo stesso IP e la stessa porta di destinazione. Gli orari delle catture TIM e
Iliad sono quelli del telefono (fuso +02:00); quelli della cattura dalla Turchia sono quelli dell'emulatore (UTC) e non
sono sincronizzati con gli altri.
