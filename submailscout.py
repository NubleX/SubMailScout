import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import time

def harvest_emails(html_content):
    """Extract email addresses from HTML content."""
    emails = set(re.findall(r'[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}', html_content))
    return emails

def get_links(domain):
    """Get all links from the given domain."""
    try:
        response = requests.get(domain, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(domain, a_tag['href'])
            if domain in link:
                links.add(link)
        return links
    except Exception as e:
        print(f"Error fetching links from {domain}: {e}")
        return set()

def find_subdomains_by_dns(domain):
    """Find subdomains by querying DNS."""
    subdomains = set()
    print("[INFO] Querying DNS for subdomains...")
    try:
        resolver = dns.resolver.Resolver()
        for record_type in ['A', 'CNAME']:
            try:
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    subdomains.add(answer.target.to_text().strip('.'))
            except Exception:
                pass
    except Exception as e:
        print(f"Error finding subdomains: {e}")
    return list(subdomains)

def fetch_subdomain_data(subdomain):
    """Fetch emails and links from a single subdomain."""
    url = f"http://{subdomain}"
    emails = set()
    links = set()
    try:
        print(f"[INFO] Fetching data from {url}")
        response = requests.get(url, timeout=10)
        emails.update(harvest_emails(response.text))
        links.update(get_links(url))
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return subdomain, emails, links

def main():
    print("Email Harvester and Subdomain Enumerator")
    domain = input("Enter the target domain (e.g., example.com): ").strip()

    print("\n[+] Enumerating subdomains...")
    start_time = time.time()
    dns_subdomains = find_subdomains_by_dns(domain)
    subdomains = set(dns_subdomains)
    elapsed_time = time.time() - start_time
    print(f"[+] Found {len(subdomains)} subdomains in {elapsed_time:.2f} seconds.")

    print("\n[+] Extracting links and harvesting emails...")
    emails = set()
    all_links = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_subdomain_data, subdomain) for subdomain in subdomains]
        for future in futures:
            subdomain, sub_emails, sub_links = future.result()
            emails.update(sub_emails)
            all_links.update(sub_links)

    print(f"[+] Found {len(emails)} email addresses.")
    print(f"[+] Found {len(all_links)} links.")

    # Print results
    print("\n--- Results ---")
    print("Subdomains:")
    for subdomain in subdomains:
        print(subdomain)

    print("\nEmails:")
    for email in emails:
        print(email)

    print("\nLinks:")
    for link in all_links:
        print(link)

if __name__ == "__main__":
    main()
