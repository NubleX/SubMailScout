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
import json

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
    pattern = r'("|')(\/[\w\d\?\/&=#.!:_-]+)("|')'
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
        print(f"[INFO] Scanning URL: {url}")
        response = request_with_delay(url)
        emails.update(harvest_emails(response.text))
        # Additional scraping from scripts
        soup = BeautifulSoup(response.text, 'html5lib')
        scripts = soup.find_all('script')
        for script in scripts:
            try:
                if script.get('src') and script['src'].startswith('/'):
                    script_url = urljoin(url, script['src'])
                    print(f"[DEBUG] Fetching script: {script_url}")
                    script_response = request_with_delay(script_url)
                    emails.update(harvest_emails(script_response.text))
            except Exception as e:
                print(f"Error fetching script: {e}")
    except Exception as e:
        print(f"Error fetching emails from {url}: {e}")
    return emails

def scan_directories(base_url):
    """Scan directories on the domain for additional paths."""
    directories = set()
    common_paths = ["admin", "login", "dashboard", "user", "api", "wp-admin", "uploads", "images"]
    for path in common_paths:
        url = urljoin(base_url, path)
        try:
            print(f"[INFO] Scanning directory: {url}")
            response = request_with_delay(url)
            if response.status_code == 200:
                directories.add(url)
        except Exception as e:
            print(f"Error scanning directory {url}: {e}")
    return directories

def enumerate_subdomains(domain):
    """Enumerate subdomains using multiple online sources."""
    subdomains = set()
    engines = ["https://crt.sh/?q=%25.{domain}",
               "https://api.sublist3r.com/search.php?domain={domain}"]

    for engine in engines:
        try:
            engine_url = engine.format(domain=domain)
            print(f"[INFO] Querying: {engine_url}")
            response = request_with_delay(engine_url)
            subdomains.update(re.findall(r'\b(?:[a-zA-Z0-9.-]+\.){1,}[a-zA-Z]{2,}\b', response.text))
        except Exception as e:
            print(f"Error querying {engine}: {e}")

    # Filter and sort unique subdomains
    subdomains = {sub for sub in subdomains if domain in sub and sub != domain}
    return subdomains

def fetch_emails_and_subdomains(base_url, domain):
    """Fetch emails and map subdomains from the specified domain."""
    emails = set()
    directories = set()

    print("[INFO] Enumerating subdomains...")
    subdomains = enumerate_subdomains(domain)

    for subdomain in subdomains:
        sub_url = f"http://{subdomain}"
        print(f"[INFO] Processing subdomain: {sub_url}")
        emails.update(fetch_emails_from_url(sub_url))

        # Scan directories in the subdomain
        directories.update(scan_directories(sub_url))

    # Fetch emails and directories from the main domain
    print(f"[INFO] Processing main domain: {base_url}")
    emails.update(fetch_emails_from_url(base_url))
    directories.update(scan_directories(base_url))

    return emails, directories, subdomains

def main():
    disable_insecure_request_warning()

    print("Enter the target domain (e.g., example.com):", end=" ")
    target_domain = input().strip()

    print("\n[+] Mapping the domain and harvesting emails...")
    start_time = time.time()

    base_url = f"http://{target_domain}"
    emails, directories, subdomains = fetch_emails_and_subdomains(base_url, target_domain)

    elapsed_time = time.time() - start_time
    print(f"[+] Found {len(emails)} email addresses, {len(directories)} directories, and {len(subdomains)} subdomains in {elapsed_time:.2f} seconds.")

    # Print results
    print("\n--- Results ---")
    print("Emails:")
    for email in emails:
        print(email)

    print("\nDirectories:")
    for directory in directories:
        print(directory)

    print("\nSubdomains:")
    for subdomain in subdomains:
        print(subdomain)

if __name__ == "__main__":
    main()
