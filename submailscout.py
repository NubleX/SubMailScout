import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import time

def regex(content):
    """Extract internal paths and resources from content."""
    pattern = r'("|\')(\/[^\"\']*?)("|\')'
    matches = re.findall(pattern, content)
    return [match[1] for match in matches]

def harvest_emails(html_content):
    """Extract email addresses from HTML content, filtering valid emails."""
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', html_content))
    valid_emails = {email for email in emails if not email.endswith(('.js', '.css', '.jpg', '.png', '.gif', '.svg'))}
    return valid_emails

def download_and_scan_file(url):
    """Download and scan file types for emails."""
    file_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ods']
    emails = set()
    try:
        response = requests.get(url, stream=True, timeout=10, verify=False)
        content_type = response.headers.get('Content-Type', '').lower()
        if any(ext in content_type for ext in file_extensions):
            file_content = response.content.decode(errors='ignore')
            emails.update(harvest_emails(file_content))
    except Exception as e:
        print(f"Error processing file {url}: {e}")
    return emails

def get_links_and_resources(url):
    """Fetch links and resources from a given URL."""
    dir_arr = []
    try:
        response = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            try:
                if script['src'] and script['src'].startswith('/'):
                    dir_arr.append(urljoin(url, script['src']))
            except KeyError:
                pass
        # Extract additional paths using regex on the HTML content
        regex_paths = regex(response.text)
        dir_arr.extend([urljoin(url, path) for path in regex_paths])
    except Exception as e:
        print(f"Error fetching resources from {url}: {e}")
    return set(dir_arr)

def fetch_data(subdomain):
    """Fetch emails and resources from a single subdomain."""
    url = f"http://{subdomain}"
    emails = set()
    resources = set()
    try:
        print(f"[INFO] Fetching data from {url}")
        response = requests.get(url, timeout=10)
        emails.update(harvest_emails(response.text))
        resources.update(get_links_and_resources(url))

        # Check resources for downloadable files
        for resource in resources:
            emails.update(download_and_scan_file(resource))
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return subdomain, emails, resources

def main():
    print("Email Harvester and Resource Enumerator")
    domain = input("Enter the target domain (e.g., example.com): ").strip()

    print("\n[+] Fetching resources and emails...")
    start_time = time.time()

    emails = set()
    all_resources = set()

    # Multi-threaded fetching
    with ThreadPoolExecutor(max_workers=10) as executor:
        future = executor.submit(fetch_data, domain)
        subdomain, sub_emails, sub_resources = future.result()
        emails.update(sub_emails)
        all_resources.update(sub_resources)

    elapsed_time = time.time() - start_time
    print(f"[+] Found {len(emails)} email addresses in {elapsed_time:.2f} seconds.")
    print(f"[+] Found {len(all_resources)} resources.")

    # Print results
    print("\n--- Results ---")
    print("Emails:")
    for email in emails:
        print(email)

    print("\nResources:")
    for resource in all_resources:
        print(resource)

if __name__ == "__main__":
    main()
