# blind-sql-injection-detector

I've developed my own blind SQL vulnerability detector that operates with remarkable precision. It swiftly identifies any alterations in the server response's body or status code. Leveraging insights from this report (https://hackerone.com/reports/2051931).
```
> python detector.py -t targets.txt -c 20 -p http
> python detector.py -t targets.txt -c 20 -p http -o results.txt
> python detector.py -t targets.txt -c 20
```
