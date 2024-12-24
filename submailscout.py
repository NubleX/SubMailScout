import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
from fake_useragent import UserAgent
import socket
from contextlib import closing
import json
import logging
import aiohttp
import asyncio
from typing import Set, Tuple, Dict
import tqdm
import dns.resolver

class WebScanner:
    def __init__(self, base_url: str, max_workers: int = 10, timeout: int = 10):
        # Ensure base_url has proper format
        self.base_url = base_url if base_url.startswith(('http://', 'https://')) else f'http://{base_url}'
        self.domain = urlparse(self.base_url).netloc
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = self._create_session()
        self.visited_urls = set()
        self.rate_limiter = asyncio.Semaphore(5)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _create_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session with custom headers and configuration."""
        return aiohttp.ClientSession(
            headers={
                "User-Agent": UserAgent().random,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            },
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )

    async def fetch_url(self, url: str) -> Tuple[str, int]:
        """Fetch URL content with rate limiting and error handling."""
        async with self.rate_limiter:
            try:
                # Ensure URL is properly formatted
                if not url.startswith(('http://', 'https://')):
                    url = urljoin(self.base_url, url)
                
                self.logger.info(f"Fetching: {url}")
                await asyncio.sleep(random.uniform(0.5, 1.5))  # Polite delay
                async with self.session.get(url, ssl=False) as response:
                    content = await response.text()
                    return content, response.status
            except aiohttp.ClientError as e:
                self.logger.error(f"Connection error for {url}: {str(e)}")
                return "", 0
            except Exception as e:
                self.logger.error(f"Error fetching {url}: {str(e)}")
                return "", 0

    async def scan_directories(self) -> Set[str]:
        """Scan common directories with improved URL handling."""
        common_paths = [
            "admin", "login", "dashboard", "user", "api", "wp-admin", 
            "uploads", "images", "includes", "js", "css", "static",
            "media", "download", "downloads", "content", "assets",
            "backup", "db", "sql", "dev", "test", "staging"
        ]
        
        directories = set()
        async def check_directory(path: str):
            try:
                # Properly join the base URL with the path
                url = urljoin(self.base_url, path)
                self.logger.info(f"Checking directory: {url}")
                content, status = await self.fetch_url(url)
                
                if status == 200:
                    directories.add(url)
                    # Also check for potential sensitive files
                    for ext in ['.php', '.txt', '.html', '.xml', '.json']:
                        file_url = urljoin(url + '/', 'index' + ext)
                        file_content, file_status = await self.fetch_url(file_url)
                        if file_status == 200:
                            directories.add(file_url)
            except Exception as e:
                self.logger.error(f"Error checking directory {path}: {str(e)}")

        # Create tasks for all directories
        tasks = [check_directory(path) for path in common_paths]
        await asyncio.gather(*tasks)
        return directories

    async def enumerate_subdomains(self) -> Set[str]:
        """Enumerate subdomains using multiple techniques."""
        subdomains = set()
        
        # DNS enumeration
        async def check_dns_record(subdomain: str):
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, dns.resolver.resolve, f"{subdomain}.{self.domain}", 'A'
                )
                if answers:
                    subdomains.add(f"{subdomain}.{self.domain}")
            except:
                pass

        # Common subdomain prefixes
        common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server',
                           'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                           'staging', 'test', 'portal', 'admin']

        tasks = [check_dns_record(sub) for sub in common_subdomains]
        await asyncio.gather(*tasks)
        
        # Certificate transparency logs
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '').lower()
                        if name.endswith(self.domain):
                            subdomains.add(name)
        except Exception as e:
            self.logger.error(f"Error querying certificate logs: {e}")

        return subdomains

    async def scan(self) -> Dict:
        """Main scanning function with progress reporting."""
        self.logger.info(f"Starting scan of {self.base_url}")
        start_time = time.time()

        # Parallel scanning
        emails = set()
        directories = await self.scan_directories()
        subdomains = await self.enumerate_subdomains()

        # Scan found locations for emails
        urls_to_scan = {self.base_url}
        urls_to_scan.update(directories)
        urls_to_scan.update(f"http://{sub}" for sub in subdomains)

        async def scan_url(url: str):
            content, _ = await self.fetch_url(url)
            found_emails = await self.find_emails(content)
            emails.update(found_emails)

        tasks = [scan_url(url) for url in urls_to_scan]
        with tqdm.tqdm(total=len(tasks), desc="Scanning URLs") as pbar:
            for task in asyncio.as_completed(tasks):
                await task
                pbar.update(1)

        elapsed_time = time.time() - start_time
        
        results = {
            "emails": sorted(list(emails)),
            "directories": sorted(list(directories)),
            "subdomains": sorted(list(subdomains)),
            "scan_time": f"{elapsed_time:.2f} seconds",
            "total_urls_scanned": len(urls_to_scan)
        }

        # Save results to file
        with open('scan_results.json', 'w') as f:
            json.dump(results, f, indent=4)

        self.logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        return results

    async def close(self):
        """Clean up resources."""
        await self.session.close()

async def main():
    print("Enter the target domain (e.g., example.com):", end=" ")
    target_domain = input().strip()
    
    scanner = WebScanner(target_domain)
    try:
        results = await scanner.scan()
        
        print("\n=== Scan Results ===")
        print(f"\nEmails found ({len(results['emails'])}):")
        for email in results['emails']:
            print(f"  - {email}")
            
        print(f"\nDirectories found ({len(results['directories'])}):")
        for directory in results['directories']:
            print(f"  - {directory}")
            
        print(f"\nSubdomains found ({len(results['subdomains'])}):")
        for subdomain in results['subdomains']:
            print(f"  - {subdomain}")
            
        print(f"\nScan completed in {results['scan_time']}")
        print(f"Total URLs scanned: {results['total_urls_scanned']}")
        print("\nFull results have been saved to 'scan_results.json'")
        
    finally:
        await scanner.close()

if __name__ == "__main__":
    asyncio.run(main())
