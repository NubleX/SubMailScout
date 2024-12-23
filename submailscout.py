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

def fetch_emails_and_subdomains(base_url):
    """Fetch emails and map subdomains from the specified domain."""
    emails = set()
    directories = set()
    visited = set()
    to_visit = {base_url}

    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        print(f"[INFO] Fetching emails from: {current_url}")
        emails.update(fetch_emails_from_url(current_url))

        # Parse robots.txt for potential subdomains or paths
        if current_url == base_url:
            new_urls = parse_robots_txt(base_url)
            to_visit.update(new_urls)
            directories.update(scan_directories(base_url))
            print(f"[DEBUG] Found {len(new_urls)} new URLs and {len(directories)} directories.")

    return emails, directories

def main():
    disable_insecure_request_warning()

    print("Enter the target domain (e.g., example.com):", end=" ")
    target_domain = input().strip()

    print("\n[+] Mapping the domain and harvesting emails...")
    start_time = time.time()

    base_url = f"http://{target_domain}"
    emails, directories = fetch_emails_and_subdomains(base_url)

    elapsed_time = time.time() - start_time
    print(f"[+] Found {len(emails)} email addresses and {len(directories)} directories in {elapsed_time:.2f} seconds.")

    # Print results
    print("\n--- Results ---")
    print("Emails:")
    for email in emails:
        print(email)

    print("\nDirectories:")
    for directory in directories:
        print(directory)

if __name__ == "__main__":
    main()
