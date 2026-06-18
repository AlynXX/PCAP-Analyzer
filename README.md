# PCAP Analyzer

Prosty analizator plikow z Wiresharka (`.pcap` i `.pcapng`).

Funkcje:

- odczyt plikow PCAP oraz PCAPNG bez dodatkowych bibliotek,
- statystyki liczby pakietow, bajtow i czasu trwania przechwycenia,
- ranking najczestszych protokolow,
- ranking najaktywniejszych hostow i najczestszych polaczen,
- prosty risk score w skali 0-100,
- raport HTML z podsumowaniem i tabelami,
- wykrywanie podejrzanych wzorcow: skanowanie portow, duzo pakietow SYN, ruch do uslug podwyzszonego ryzyka, nietypowo duzo DNS.

## Uruchomienie

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

Po instalacji pakietu lokalnie dostepna jest tez komenda:

```powershell
pip install -e .
pcap-analyzer sample.pcap
```

## Testy

```powershell
python -m unittest discover -s tests
```
