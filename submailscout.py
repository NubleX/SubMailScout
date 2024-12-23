import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import time
import random
from fake_useragent import UserAgent
import socket
from contextlib import closing
import argparse

# Disable insecure request warnings
def disable_insecure_request_warning():
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_random_user_agent():
    """Generate a random User-Agent string."""
    ua = UserAgent()
    return ua.random

def request_with_delay(url, verify=False):
    """Make a request with a random delay and User-Agent."""
    headers = {"User-Agent": get_random_user_agent()}
    time.sleep(random.uniform(0.5, 2.0))  # Random delay between 0.5 to 2 seconds
    response = requests.get(url, headers=headers, verify=verify, timeout=10)
    drop_connection(response)
    return response

def drop_connection(response):
    """Close the socket connection to drop the handshake."""
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.close()
    except Exception as e:
        print(f"Error dropping connection: {e}")

def harvest_emails(content):
    """Extract email addresses from content, filtering valid emails."""
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', content))
    valid_emails = {email for email in emails if not email.endswith(('.js', '.css', '.jpg', '.png', '.gif', '.svg'))}
    return valid_emails

def regex(content):
    pattern = r'(\"|\')(\/[^\"\']*?)(\"|\')'
    matches = re.findall(pattern, content)
    response = ""
    i = 0
    for match in matches:
        i += 1
        if i == len(matches):
            response += match[1]
        else:
            response += match[1] + "\n"
    return response

def parse_robots_txt(base_url):
    """Parse the robots.txt file for additional URLs."""
    urls = set()
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        response = request_with_delay(robots_url)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.lower().startswith('allow:') or line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and not path.startswith('#'):
                        urls.add(urljoin(base_url, path))
    except Exception as e:
        print(f"Error fetching robots.txt: {e}")
    return urls

def fetch_emails_from_url(url):
    """Fetch emails from the specified URL."""
    emails = set()
    try:
        response = request_with_delay(url)
        emails.update(harvest_emails(response.text))
        # Additional scraping from scripts
        soup = BeautifulSoup(response.text, 'html5lib')
        scripts = soup.find_all('script')
        for script in scripts:
            try:
                if script.get('src') and script['src'].startswith('/'):
                    script_url = urljoin(url, script['src'])
                    script_response = request_with_delay(script_url)
                    emails.update(harvest_emails(script_response.text))
            except Exception as e:
                print(f"Error fetching script: {e}")
    except Exception as e:
        print(f"Error fetching emails from {url}: {e}")
    return emails

def fetch_emails_and_subdomains(base_url):
    """Fetch emails and map subdomains from the specified domain."""
    emails = set()
    visited = set()
    to_visit = {base_url}

    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        print(f"[DEBUG] Fetching emails from: {current_url}")
        emails.update(fetch_emails_from_url(current_url))

        # Parse robots.txt for potential subdomains or paths
        if current_url == base_url:
            to_visit.update(parse_robots_txt(base_url))

    return emails

def main():
    disable_insecure_request_warning()
    parser = argparse.ArgumentParser(description='Email Harvester and Subdomain Mapper')
    parser.add_argument('-u', help='Target domain (e.g., example.com)', required=True)
    parser.add_argument('-o', help='Output file for emails.', nargs="?")
    args = parser.parse_args()

    print("\n[+] Mapping the domain and harvesting emails...")
    start_time = time.time()

    base_url = f"http://{args.u}"
    emails = fetch_emails_and_subdomains(base_url)

    elapsed_time = time.time() - start_time
    print(f"[+] Found {len(emails)} email addresses in {elapsed_time:.2f} seconds.")

    # Print results
    print("\n--- Results ---")
    print("Emails:")
    for email in emails:
        print(email)

    # Save results to file if specified
    if args.o:
        with open(args.o, 'w') as f:
            for email in emails:
                f.write(email + '\n')

if __name__ == "__main__":
    main()
