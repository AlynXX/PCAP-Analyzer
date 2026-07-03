# PCAP Analyzer

Prosty analizator plikow z Wiresharka (`.pcap` i `.pcapng`).

Funkcje:

- odczyt plikow PCAP oraz PCAPNG bez dodatkowych bibliotek,
- statystyki liczby pakietow, bajtow i czasu trwania przechwycenia,
- ranking najczestszych protokolow,
- ranking najaktywniejszych hostow i najczestszych polaczen,
- analiza sesji/flow z liczba pakietow, bajtow i czasem trwania,
- eksport pelnej listy pakietow do CSV,
- wykrywanie prostych anomalii czasowych,
- prosty risk score w skali 0-100,
- raport HTML z podsumowaniem, tabelami i prostymi wykresami,
- lokalny interfejs webowy do uploadu i analizy pliku,
- eksport CSV,
- filtrowanie po hoscie, protokole i porcie,
- porownywanie dwoch plikow PCAP,
- generator przykladowego PCAP,
- rozpoznawanie popularnych protokolow aplikacyjnych po portach,
- wykrywanie podejrzanych wzorcow: skanowanie portow, duzo pakietow SYN, ruch do uslug podwyzszonego ryzyka, nietypowo duzo DNS.

## Uruchomienie

Instalacja:

```powershell
pip install .
```

Tryb developerski:

```powershell
pip install -e .
```

```powershell
python -m pcap_analyzer sample.pcap
```

Wynik w JSON:

```powershell
python -m pcap_analyzer sample.pcapng --json
```

Raport HTML:

```powershell
python -m pcap_analyzer sample.pcap --html report.html
```

Lokalne GUI:

```powershell
python -m pcap_analyzer --gui
```

Nastepnie otworz w przegladarce `http://127.0.0.1:8080`.

Eksport CSV:

```powershell
python -m pcap_analyzer sample.pcap --csv wyniki
```

Eksport CSV tworzy pliki: `summary.csv`, `protocols.csv`, `talkers.csv`,
`connections.csv`, `flows.csv`, `packets.csv` i `suspicious.csv`.

Filtrowanie:

```powershell
python -m pcap_analyzer sample.pcap --host 192.168.1.10
python -m pcap_analyzer sample.pcap --protocol HTTPS
python -m pcap_analyzer sample.pcap --port 443
```

Krotkie podsumowanie bez tabel:

```powershell
python -m pcap_analyzer sample.pcap --summary-only
```

Porownanie dwoch plikow:

```powershell
python -m pcap_analyzer before.pcap --compare after.pcap
```

Przykladowy PCAP do demonstracji:

```powershell
python -m pcap_analyzer --generate-sample sample.pcap
```

Po instalacji pakietu lokalnie dostepna jest tez komenda:

```powershell
pcap-analyzer sample.pcap
```

## Dokumentacja

Opis architektury, algorytmow, regulek IDS-like i ograniczen znajduje sie w
[`docs/technical.md`](docs/technical.md).

## Testy

```powershell
python -m unittest discover -s tests
```
