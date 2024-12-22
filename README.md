# SubMailScout
Program that combines website enumeration, domain/subdomain discovery, and email harvesting.

### Key Features:
1. **Website Crawling**:
   - Extracts all links from the target domain.
   - Ensures only links within the same domain are included.

2. **Subdomain Enumeration**:
   - Uses a wordlist to identify possible subdomains by attempting DNS resolution.

3. **Email Harvesting**:
   - Finds and extracts email addresses from the crawled pages using regex.

### Prerequisites:
- Install the required Python libraries:
  ```bash
  pip install -r requirements.txt
  ```
- Prepare a wordlist file for subdomain discovery (e.g., `wordlist.txt`).

### Usage:
1. Run the script:
   ```bash
   python submailscout.py
   ```
2. Enter the target domain (e.g., `https://example.com`) and the path to your subdomain wordlist.
3. View the enumerated links, subdomains, and emails.
