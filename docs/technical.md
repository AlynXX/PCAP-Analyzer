# PCAP Analyzer - dokumentacja techniczna

## Architektura

Projekt sklada sie z kilku warstw:

- `pcap_analyzer.parser` - odczyt PCAP/PCAPNG i parsowanie Ethernet, IPv4, IPv6, TCP, UDP, ICMP oraz ARP.
- `pcap_analyzer.analyzer` - agregacja statystyk, flow, pakietow i risk score.
- `pcap_analyzer.rules` - reguly wykrywania zdarzen podobne do prostego IDS.
- `pcap_analyzer.report` - samodzielny raport HTML.
- `pcap_analyzer.csv_export` - eksport tabel CSV.
- `pcap_analyzer.compare` - porownywanie dwoch wynikow analizy.
- `pcap_analyzer.gui` - lokalny interfejs webowy oparty o standardowa biblioteke Pythona.
- `pcap_analyzer.cli` - interfejs terminalowy.

Projekt celowo nie wymaga zewnetrznych bibliotek. Dzieki temu mozna go uruchomic
po samym `pip install .`, ale parser obsluguje tylko wybrane, najczestsze
warstwy protokolow.

## Pipeline analizy

1. Plik PCAP/PCAPNG jest czytany jako rekordy binarne.
2. Kazdy rekord jest parsowany do `ParsedPacket`.
3. Opcjonalne filtry `host`, `protocol`, `port` odrzucaja niepasujace pakiety.
4. `analyze_packets()` liczy:
   - liczbe pakietow i bajtow,
   - czas trwania,
   - najczestsze protokoly,
   - najaktywniejsze hosty,
   - polaczenia kierunkowe,
   - flow dwukierunkowe,
   - pelne streszczenia pakietow,
   - alerty regulek.
5. Alerty sa przeliczane na risk score 0-100.
6. Wynik mozna zapisac jako JSON, CSV, HTML albo obejrzec w GUI.

## Reguly IDS-like

Reguly znajduja sie w `pcap_analyzer.rules`. Kazdy alert ma:

- `rule_id`,
- `severity`,
- `title`,
- `details`,
- `evidence`.

Obecne reguly:

- `PORT_SCAN` - wiele portow lub hostow z jednego zrodla.
- `SYN_FLOOD` - wiele pakietow SYN bez ACK.
- `RISKY_SERVICE` - ruch do portow administracyjnych i ryzykownych.
- `DNS_SPIKE` - nietypowo duzo pakietow DNS.
- `EXTERNAL_TO_PRIVATE` - ruch z adresu publicznego do prywatnego.
- `PACKET_BURST` - duza liczba pakietow w jednej sekundzie.
- `NULL_SCAN` - pakiety TCP bez flag.
- `XMAS_SCAN` - pakiety TCP z FIN, PSH i URG.
- `FIN_SCAN` - wiele pakietow FIN bez ACK.
- `SMB_OR_RDP_EXPOSURE` - ruch do SMB lub RDP.

## Risk score

Risk score jest prosta suma wag alertow:

- `niskie` - 10 punktow,
- `srednie` - 25 punktow,
- `wysokie` - 70 punktow.

Jesli alertow jest co najmniej 5, dodawane jest 10 punktow. Wynik jest obcinany
do 100. Poziomy:

- `brak`: 0,
- `niskie`: 1-34,
- `srednie`: 35-69,
- `wysokie`: 70-100.

## Ograniczenia

- Klasyfikacja aplikacyjna jest oparta glownie o porty, nie o inspekcje payloadu.
- PCAPNG timestamp resolution jest uproszczone do mikrosekund.
- Nie sa obslugiwane wszystkie link types, tunele, fragmentacja IP ani pelne rozszerzenia IPv6.
- Alerty sa heurystyczne i edukacyjne; projekt nie jest pelnym IDS/IPS.
- GUI jest lokalne i przeznaczone do pracy na zaufanym komputerze.

## Instalacja i uruchomienie

Instalacja lokalna:

```powershell
pip install .
```

Tryb developerski:

```powershell
pip install -e .
```

Po instalacji dostepna jest komenda:

```powershell
pcap-analyzer sample.pcap
```

GUI:

```powershell
pcap-analyzer --gui
```

Testy:

```powershell
python -m unittest discover -s tests
```
