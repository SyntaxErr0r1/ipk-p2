Meno: Juraj Dedič  
Login: xdedic07  
Varianta ZETA: Sniffer paketů

## Popis
Program slúži na filtrovanie a výpis informácií o paketoch.
Umožňuje filtrovať podľa protokolu či portu.
Zobrazuje informácie ako sú MAC adresy, IP adresy, porty a taktiež celý paket.
Zachytáva pakety na zvolenom sieťovom rozhraní.

## Použitie

Program sa spúšťa pomocou príkazu ./ipk-sniffer parametre.
Kde parametre môžu byť:
- `--interface {rozhranie}`, `-i {rozhranie}`: Udáva na akom rozhraní bude program zbierať pakety. V prípade že rozhranie nieje zadané, zobrazí zoznam rozhraní.
- `--tcp`, `-t`: Program bude filtrovať pakety s protokolom TCP.
- `--udp`, `-u`: Program bude filtrovať pakety s protokolom UDP.
- `--arp`: Program bude filtrovať pakety s protokolom ARP.
- `--icmp`: Program bude filtrovať pakety s protokolom ICMP.
- `-n [počet]`: Špecifikuje počet paketov ktoré budú prijaté a zobrazené, predvolený počet je 1.
- `-p [port]`: Vybere, ktorý port bude filtrovaný

Ak nieke zadaný žiaden protokol, ktorý treba filtrovať, bude sa zobrazovať každý z týchto protokolov.
V prípade, že je zadaných viacej protokolov, ale nie všetky, budú sa zobrazovať zadané protokoly. 
Ak je špecifikovaný port, obmedzenie tohoto portu sa bude vzťahovať len pre protokoly TCP a UDP, pri ostatných sa tento filter vynechá.
### Príklady použitia
- Pre zobrazenie dostupných sieťových rozhraní: `./ipk-sniffer`
- Zobrazenie prvých 5 ARP paketov na rozhraní `lo`: `./ipk-sniffer -i lo --arp -n 5`
- Zobrazí TCP alebo UDP paket na rozhraní `eth0`: `./ipk-sniffer -i eth0 -t --udp`
- Ukáže TCP paket na porte 80 na rozhraní `eth0`: `./ipk-sniffer -i eth0 --tcp -p 80`
- Vypíše prvé 2 ICMP pakety na rozhraní `eth0`: `./ipk-sniffer --interface eth0 --icmp -n 2`
- Zachytí 20 paketov hociktorého z podporovaných typov na zariadení `lo`: `./ipk-sniffer -i lo -n 20`
- Zachytí ICMP alebo TCP pakety s portom 80 (v prípade ICMP bude zadaný port ignorovaný): `./ipk-sniffer -i eth0 --icmp -t -p 80`

## Požiadavky
Unixový systém so sieťovým rozhraním. Pre kompiláciu je potrebná knižnica libpcap. Zachytávané pakety majú  LINKTYPE_ETHERNET.


Testované v prostrediach:
- Debian GNU/Linux 10 (buster) (WSL)
- Ubuntu 20.04 (Oracle VM Virtualbox)