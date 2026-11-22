# 🚗 Guida: Connettività Mobile, Auto Connesse e Risoluzione Conflitti VPN (Android Auto & CarPlay)

## 1. Il Problema: Errore di Comunicazione 21 su Android Auto / CarPlay Wireless

Quando si attiva una VPN su smartphone (es. WireGuard o OpenVPN connessi al proprio Home Server con Sentinel) e si tenta di avviare **Android Auto Wireless** o **Apple CarPlay Wireless**, l'infotainment dell'auto o lo schermo del telefono mostrano un errore bloccante:

> **"Si è verificato un errore in Android Auto - Errore di comunicazione 21: La connessione a una VPN potrebbe impedire l'avvio di Android Auto. Se stai usando una VPN, disattivala e riprova."**

### Causa Tecnica Radice (Root Cause)
1. **Architettura di Proiezione Wireless P2P**: 
   - Android Auto e Apple CarPlay wireless utilizzano prima una connessione Bluetooth a bassa energia (BLE) per scambiarsi credenziali e poi avviano un hotspot Wi-Fi Direct P2P ad alta velocità tra smartphone e head unit (tipicamente su subnet `192.168.43.0/24` o `192.168.49.0/24`).
   - I dati video (H.264/H.265) e audio vengono trasmessi su socket TCP/IP locali diretti verso l'indirizzo della macchina (es. `192.168.43.1`).
2. **Cattura della Tabella di Routing da parte della VPN**:
   - Se il profilo WireGuard è configurato con `AllowedIPs = 0.0.0.0/0, ::/0` (Full-Tunnel), il kernel Android instrada **tutti i pacchetti IP** nell'interfaccia di rete virtuale della VPN (`tun0`).
   - I pacchetti diretti alla macchina vengono spediti al server domestico invece che all'interfaccia Wi-Fi Direct locale. L'handshake fallisce e Android Auto termina con **Errore 21**.

---

## 2. La Risoluzione: Split Tunneling su WireGuard (Android)

Per continuare a godere della protezione cyber di Sentinel quando sei fuori casa senza rompere la connessione dell'auto:

1. Apri l'app **WireGuard** sul tuo smartphone Android.
2. Tocca il nome del tuo tunnel (es. `Home-Sentinel`).
3. Tocca l'icona della **Matita (Modifica)** in alto a destra.
4. Scorri verso il basso fino alla voce **Applicazioni escluse (Excluded Applications)** o **Tunneling frazionato**.
5. Cerca e spunta:
   - ✅ **Android Auto** (nome package: `com.google.android.projection.gearhead`)
6. Tocca l'icona del **Disco (Salva)** in alto a destra.
7. Riconnetti il tunnel WireGuard.

> [!TIP]
> Una volta applicata questa configurazione, Android instrada il traffico di Android Auto direttamente all'hotspot Wi-Fi dell'auto, mentre tutte le query DNS e la navigazione del browser e delle app continuano a essere protette e filtrate dal tuo Sentinel a casa.

---

## 3. Telemetria Automobilistica vs App Compagne (Tesla, BMW, Mercedes)

I veicoli moderni dispongono di due flussi di rete distinti:

| Canale di Rete | Scopo | Trattamento Sentinel |
| :--- | :--- | :--- |
| **Control Plane (App Ufficiale)** | Pre-climatizzazione, sblocco portiere, stato batteria | **SEMPRE CONSENTITO** (`owner-api.teslamotors.com`, `b2vapi.bmwgroup.com`) |
| **Data Plane (Broker Assicurativi)** | Vendita a terzi di frenate brusche, accelerazioni, velocità notturna | **BLOCCATO DETERMINISTICAMENTE** (`telemetry.lexisnexis.com`, `risk.lexisnexis.com`, `telematics.verisk.com`, `otonomo.io`) |

I profili nel file `sources/device_profiles.yaml` garantiscono che l'app sul telefono continui a comandare il veicolo senza intoppi, mentre i broker che alzano i premi della tua polizza RCA vengono neutralizzati.

---

## 4. Evoluzione Hardware: Sentinel Drive Dongle

Per le vetture che non consentono la modifica del DNS sui modem 4G/5G integrati dell'abitacolo, il progetto Sentinel include le specifiche per **Sentinel Drive**:
- Dongle compatto basato su ESP32 o Raspberry Pi Zero 2W inserito nella presa USB o porta OBD-II dell'auto.
- Crea l'hotspot dell'abitacolo con DNS sinkholing locale a bordo del veicolo.
- Isola nativamente l'infotainment senza dipendere da tunnel VPN su smartphone.
