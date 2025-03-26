#!/usr/bin/env python3
"""
Gmail Checker Wrapper

This script provides a simple wrapper around the gmail_checker.py module
with colorized output and better error handling.
"""

import sys
import argparse
import logging
import json
from typing import List, Dict, Any
from colorama import init, Fore, Style
from gmail_checker import GmailChecker, HttpVerificationStrategy, EmailVerificationResult

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_emails(emails: List[str], proxy_file: str, max_workers: int = 3, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Check if Gmail addresses are registered.
    
    Args:
        emails: List of email addresses to check
        proxy_file: Path to the proxy file
        max_workers: Maximum number of worker threads
        verbose: Enable verbose logging
    
    Returns:
        List of results
    """
    # Set logging level
    if verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create checker with HTTP verification strategy
    checker = GmailChecker(verification_strategy=HttpVerificationStrategy())
    
    # Load proxies
    logger.info(f"Loading proxies from {proxy_file}")
    checker.load_proxies(proxy_file)
    
    # Check emails
    logger.info(f"Checking {len(emails)} emails with {max_workers} workers")
    results = checker.check_emails_batch(emails, max_workers=max_workers)
    
    # Convert results to dictionaries
    return [
        {
            "email": r.email,
            "result": r.result.value,
            "message": r.message,
            "proxy_used": r.proxy_used.address if r.proxy_used else None,
            "response_time": r.response_time
        }
        for r in results
    ]


def print_results(results: List[Dict[str, Any]]) -> None:
    """Print results with colorized output."""
    print("\n=== Gmail Checker Results ===\n")
    
    for result in results:
        email = result["email"]
        status = result["result"]
        message = result["message"]
        
        if status == EmailVerificationResult.VALID.value:
            color = Fore.RED
            status_str = "REGISTERED"
        elif status == EmailVerificationResult.INVALID.value:
            color = Fore.GREEN
            status_str = "AVAILABLE"
        elif status == EmailVerificationResult.UNKNOWN.value:
            color = Fore.YELLOW
            status_str = "UNKNOWN"
        else:
            color = Fore.MAGENTA
            status_str = "ERROR"
        
        print(f"{color}{email}: {status_str} - {message}{Style.RESET_ALL}")
    
    print("\n=== Summary ===\n")
    
    registered = sum(1 for r in results if r["result"] == EmailVerificationResult.VALID.value)
    available = sum(1 for r in results if r["result"] == EmailVerificationResult.INVALID.value)
    unknown = sum(1 for r in results if r["result"] == EmailVerificationResult.UNKNOWN.value)
    error = sum(1 for r in results if r["result"] == EmailVerificationResult.ERROR.value)
    
    print(f"{Fore.RED}Registered: {registered}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Available: {available}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Unknown: {unknown}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Error: {error}{Style.RESET_ALL}")
    print(f"Total: {len(results)}")


def save_results(results: List[Dict[str, Any]], output_file: str) -> None:
    """Save results to a file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Results saved to {output_file}")
    
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Check if Gmail addresses are registered")
    parser.add_argument("emails", nargs="*", help="Email addresses to check")
    parser.add_argument("-f", "--file", help="File containing email addresses (one per line)")
    parser.add_argument("-p", "--proxies", default="working_proxies.txt", help="Proxy file path")
    parser.add_argument("-w", "--workers", type=int, default=3, help="Number of worker threads")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Get emails to check
    emails = []
    
    if args.emails:
        emails.extend(args.emails)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_emails = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                emails.extend(file_emails)
        except Exception as e:
            logger.error(f"Error reading email file: {str(e)}")
            return 1
    
    if not emails:
        logger.error("No emails to check. Use positional arguments or --file to specify emails.")
        return 1
    
    # Add @gmail.com if not present
    emails = [email if '@' in email else f"{email}@gmail.com" for email in emails]
    
    try:
        # Check emails
        results = check_emails(emails, args.proxies, args.workers, args.verbose)
        
        # Print results
        print_results(results)
        
        # Save results to file if requested
        if args.output:
            save_results(results, args.output)
        
        return 0
    
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
