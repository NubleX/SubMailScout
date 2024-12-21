import requests
from bs4 import BeautifulSoup
import re
import dns.resolver

def harvest_emails(html_content):
    """Extract email addresses from HTML content."""
    emails = set(re.findall(r'[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}', html_content))
    return emails

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

    print("\n[+] Harvesting emails...")
    emails = set()
    for subdomain in subdomains:
        url = f"http://{subdomain}"
        try:
            response = requests.get(url, timeout=10)
            emails.update(harvest_emails(response.text))
        except Exception as e:
            print(f"Error fetching {url}: {e}")
    print(f"[+] Found {len(emails)} email addresses.")

    # Print results
    print("\n--- Results ---")
    print("Subdomains:")
    for subdomain in subdomains:
        print(subdomain)

    print("\nEmails:")
    for email in emails:
        print(email)

if __name__ == "__main__":
    main()
