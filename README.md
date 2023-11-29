# blind-sql-injection-detector

I have developed my own blind SQL vulnerability detector that works with amazing accuracy. It quickly detects any changes to the server response body or status code. 
Used information from this report https://hackerone.com/reports/2051931
```
> python detector.py -t targets.txt -c 20 -p http
> python detector.py -t targets.txt -c 20 -p http -o results.txt
> python detector.py -t targets.txt -c 20
```
