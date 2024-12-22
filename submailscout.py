import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import time
import os

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

def parse_robots_txt(base_url):
    """Parse the robots.txt file for additional URLs."""
    urls = set()
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        response = requests.get(robots_url, timeout=10, verify=False)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.lower().startswith('allow:') or line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and not path.startswith('#'):
                        urls.add(urljoin(base_url, path))
    except Exception as e:
        print(f"Error fetching robots.txt: {e}")
    return urls

def get_links_and_resources(url):
    """Fetch links and resources from a given URL."""
    dir_arr = []
    try:
        response = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(url, a_tag['href'])
            dir_arr.append(link)
        # Extract additional paths using regex on the HTML content
        regex_paths = regex(response.text)
        dir_arr.extend([urljoin(url, path) for path in regex_paths])
    except Exception as e:
        print(f"Error fetching resources from {url}: {e}")
    return set(dir_arr)

def fetch_data(base_url):
    """Fetch emails and resources from a single website."""
    emails = set()
    resources = set()
    try:
        print(f"[INFO] Fetching data from {base_url}")

        # Parse robots.txt for additional paths
        resources.update(parse_robots_txt(base_url))

        # Get links and resources from the main page
        resources.update(get_links_and_resources(base_url))

        # Process each resource for emails and downloadable files
        for resource in resources.copy():
            try:
                response = requests.get(resource, timeout=10, verify=False)
                emails.update(harvest_emails(response.text))
                emails.update(download_and_scan_file(resource))

                # Recursively fetch links and resources for deeper mapping
                sub_resources = get_links_and_resources(resource)
                resources.update(sub_resources)
            except Exception as e:
                print(f"Error processing resource {resource}: {e}")
    except Exception as e:
        print(f"Error fetching {base_url}: {e}")
    return base_url, emails, resources

def main():
    print("Email Harvester and Website Mapper")
    domain = input("Enter the target domain (e.g., example.com): ").strip()

    print("\n[+] Mapping the website and harvesting emails...")
    start_time = time.time()

    emails = set()
    all_resources = set()

    # Multi-threaded fetching
    with ThreadPoolExecutor(max_workers=10) as executor:
        future = executor.submit(fetch_data, f"http://{domain}")
        base_url, found_emails, found_resources = future.result()
        emails.update(found_emails)
        all_resources.update(found_resources)

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
