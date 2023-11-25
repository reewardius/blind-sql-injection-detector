# blind-sql-injection-detector

Wrote my own blind SQL vulnerability detector, if the body, or status code is changed in the response from the server, the scanner will report it.
Based on this report. https://hackerone.com/reports/2051931
```
> python detector.py -t targets.txt -c 20 -p http
> python detector.py -t targets.txt -c 20 -p https
```
