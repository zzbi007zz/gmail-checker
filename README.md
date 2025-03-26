# Gmail Registration Checker

A Python tool to check if Gmail addresses are registered, using free proxies to prevent IP blocking.

## Features

- Check if Gmail addresses are registered using SMTP or HTTP methods
- Use and rotate free proxies to prevent IP blocking
- Parallel processing for checking multiple emails
- Command-line interface for easy usage
- Comprehensive logging
- Proxy health monitoring

## Design Patterns Used

This project implements several design patterns to ensure maintainability, extensibility, and robustness:

1. **Strategy Pattern**: Different email verification methods (SMTP and HTTP) are implemented as strategies, allowing the client to choose the appropriate method at runtime.

2. **Factory Pattern**: Proxy objects are created using factories based on their protocol (HTTP, HTTPS, SOCKS), encapsulating the creation logic.

3. **Singleton Pattern**: The ProxyManager is implemented as a singleton to ensure a single instance manages all proxies throughout the application.

4. **Observer Pattern**: Proxy health is monitored through observers that are notified when proxy status changes.

## Installation

### Prerequisites

- Python 3.6 or higher
- Required packages: `requests`

### Setup

1. Clone or download this repository
2. Install the required packages:

```bash
pip install requests
```

## Usage

### Command Line Interface

The simplest way to use the tool is through the command line interface:

```bash
python gmail_checker.py -p proxies.txt example@gmail.com
```

#### Options

- `-p, --proxies`: Proxy source (file path or URL) [required]
- `-f, --file`: File containing email addresses (one per line)
- `-m, --method`: Verification method (`smtp` or `http`, default: `http`)
- `-w, --workers`: Number of worker threads (default: 5)
- `-o, --output`: Output file for results (JSON format)
- `-v, --verbose`: Enable verbose logging

#### Examples

Check a single email:
```bash
python gmail_checker.py -p proxies.txt example@gmail.com
```

Check multiple emails:
```bash
python gmail_checker.py -p proxies.txt example1@gmail.com example2@gmail.com
```

Check emails from a file:
```bash
python gmail_checker.py -p proxies.txt -f emails.txt
```

Use SMTP verification method:
```bash
python gmail_checker.py -p proxies.txt -m smtp example@gmail.com
```

Save results to a file:
```bash
python gmail_checker.py -p proxies.txt -o results.json example@gmail.com
```

### Programmatic Usage

You can also use the tool programmatically in your own Python code:

```python
from gmail_checker import GmailChecker, HttpVerificationStrategy

# Create a checker with HTTP verification strategy (default)
checker = GmailChecker()

# Load proxies from file
checker.load_proxies("proxies.txt")

# Check a single email
result = checker.check_email("example@gmail.com")
print(f"Result: {result.result.value}")

# Check multiple emails
emails = ["example1@gmail.com", "example2@gmail.com"]
results = checker.check_emails_batch(emails, max_workers=2)
```

See `example_usage.py` for a more detailed example.

## Proxy Sources

The tool can use proxies from different sources:

### File Format

You can provide proxies in a text file with one proxy per line in any of these formats:
- `IP:PORT` (e.g., `192.168.1.1:8080`)
- `protocol://IP:PORT` (e.g., `http://192.168.1.1:8080`)
- `protocol://username:password@IP:PORT` (e.g., `http://user:pass@192.168.1.1:8080`)

Example:
```
http://203.24.108.150:80
http://103.152.112.162:80
185.162.230.55:80
```

### API Format

You can also provide a URL to a proxy API. The tool expects the API to return JSON in one of these formats:
- An array of proxy objects
- An object with a `data` field containing an array of proxy objects

Each proxy object should have at least `host` and `port` fields, and optionally `protocol`, `username`, and `password` fields.

### Updating Proxies

The repository includes an `update_proxies.py` script that can automatically fetch fresh proxies from various public APIs and update your proxy list file:

```bash
python update_proxies.py -o sample_proxies.txt
```

#### Options

- `-o, --output`: Output file path (default: `sample_proxies.txt`)
- `-l, --limit`: Number of proxies to fetch from each source (default: 20)
- `-v, --verbose`: Enable verbose logging

This script fetches proxies from multiple sources including GeoNode, ProxyScrape, and Free-Proxy-List, removes duplicates, and saves them to the specified file.

### Testing Proxies

Before using proxies with the Gmail checker, you can test them to ensure they're working using the `test_proxies.py` script:

```bash
python test_proxies.py -i sample_proxies.txt -o working_proxies.txt
```

#### Options

- `-i, --input`: Input proxy file path (default: `sample_proxies.txt`)
- `-o, --output`: Output file for working proxies (default: `working_proxies.txt`)
- `-r, --results`: Output file for detailed test results in JSON format (default: `proxy_test_results.json`)
- `-t, --timeout`: Timeout in seconds for each proxy test (default: 5)
- `-w, --workers`: Number of worker threads (default: 10)
- `-v, --verbose`: Enable verbose logging

This script tests each proxy against multiple test URLs, measures response times, and saves only the working proxies to the output file. It also generates a detailed JSON report of all test results.

## Limitations

- Gmail has security measures that may detect and block automated verification attempts
- Free proxies are often unreliable and may be already blocked by Google
- The HTTP verification method is based on Google's current implementation and may break if Google changes their login flow

## License

This project is licensed under the MIT License - see the LICENSE file for details.
