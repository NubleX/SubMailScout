# SubMailScout - Advanced Web Reconnaissance Tool

SubMailScout is a high-performance, asynchronous web reconnaissance tool designed for comprehensive domain analysis and email discovery. It combines multiple scanning techniques to efficiently map websites, discover subdomains, and extract contact information from various document types.

## Features

- **Asynchronous Operation**: Utilizes Python's `asyncio` for high-performance concurrent scanning
- **Smart Rate Limiting**: Prevents server overload with built-in rate limiting
- **Comprehensive Scanning**:
  - Recursive webpage crawling
  - Document parsing (PDF, DOC, DOCX, XLS, XLSX)
  - Dynamic page detection
  - Directory enumeration
  - Subdomain discovery via DNS and certificate transparency logs
- **Email Extraction**:
  - Advanced pattern matching for email addresses
  - Validation and filtering of discovered emails
  - Support for various file formats
- **File Processing**:
  - Automatic file type detection
  - In-memory file processing
  - Temporary file cleanup
- **Robust Error Handling**:
  - Comprehensive logging
  - Connection error recovery
  - Invalid URL handling

## Requirements

- Python 3.7+
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nublex/submailscout.git
cd submailscout
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the scanner:
```bash
python submailscout.py
```

When prompted, enter your target domain (e.g., example.com).

The tool will:
1. Start scanning the domain recursively
2. Check common directories
3. Enumerate subdomains
4. Process any discovered documents
5. Extract and validate email addresses
6. Save results to `scan_results.json`

## Output

Results are saved in JSON format containing:
- Discovered email addresses
- Found directories
- Enumerated subdomains
- Scan statistics (duration, URLs scanned, files processed)

Example output structure:
```json
{
    "emails": ["contact@example.com", "support@example.com"],
    "directories": ["http://example.com/docs", "http://example.com/assets"],
    "subdomains": ["mail.example.com", "www.example.com"],
    "scan_time": "45.23 seconds",
    "total_urls_scanned": 150,
    "total_files_processed": 25
}
```

## Logging

The tool maintains detailed logs in `scanner.log`, including:
- URLs visited
- Files processed
- Errors encountered
- Scan progress

## Legal Disclaimer

This tool is provided for educational and ethical testing purposes only. Users are responsible for:
- Obtaining permission before scanning any domains
- Complying with all applicable laws and regulations
- Adhering to website terms of service
- Respecting robots.txt directives

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Acknowledgments

- Built with Python's asyncio for high-performance async operations
- Uses multiple open-source libraries for comprehensive file parsing
- Inspired by the need for efficient and thorough web reconnaissance
