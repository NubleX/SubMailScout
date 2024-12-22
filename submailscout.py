import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
from urllib.parse import urljoin

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

def find_subdomains(domain, wordlist):
    """Discover subdomains using a wordlist."""
    subdomains = []
    with open(wordlist, 'r') as file:
        words = file.read().splitlines()
        for word in words:
            subdomain = f"{word}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                subdomains.append(subdomain)
            except:
                pass
    return subdomains

def main():
    print("Email Harvester and Subdomain Enumerator")
    domain = input("Enter the target domain (e.g., https://example.com): ").strip()
    wordlist = input("Enter the path to your subdomain wordlist: ").strip()

    print("\n[+] Enumerating subdomains...")
    subdomains = find_subdomains(domain.replace('https://', '').replace('http://', ''), wordlist)
    print(f"[+] Found {len(subdomains)} subdomains.")

    print("\n[+] Extracting links and harvesting emails...")
    emails = set()
    all_links = set()
    for subdomain in subdomains:
        url = f"http://{subdomain}"
        try:
            response = requests.get(url, timeout=10)
            emails.update(harvest_emails(response.text))
            links = get_links(url)
            all_links.update(links)
        except Exception as e:
            print(f"Error fetching {url}: {e}")
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
