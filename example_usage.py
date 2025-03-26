#!/usr/bin/env python3
"""
Example usage of the Gmail Checker

This script demonstrates how to use the GmailChecker class to check
if Gmail addresses are registered.
"""

from gmail_checker import GmailChecker, HttpVerificationStrategy, SmtpVerificationStrategy

def main():
    # Create a checker with HTTP verification strategy (default)
    checker = GmailChecker()
    
    # Alternatively, you can use SMTP verification
    # checker = GmailChecker(verification_strategy=SmtpVerificationStrategy())
    
    # Load proxies from file
    checker.load_proxies("sample_proxies.txt")
    
    # Check a single email
    print("Checking a single email...")
    result = checker.check_email("example@gmail.com")
    print(f"Result: {result.result.value}")
    print(f"Message: {result.message}")
    if result.proxy_used:
        print(f"Proxy used: {result.proxy_used.address}")
    print(f"Response time: {result.response_time:.2f} seconds")
    print()
    
    # Check multiple emails
    print("Checking multiple emails...")
    emails = [
        "example1@gmail.com",
        "example2@gmail.com",
        "example3@gmail.com"
    ]
    
    results = checker.check_emails_batch(emails, max_workers=3)
    
    for result in results:
        print(f"Email: {result.email}")
        print(f"Result: {result.result.value}")
        print(f"Message: {result.message}")
        if result.proxy_used:
            print(f"Proxy used: {result.proxy_used.address}")
        print(f"Response time: {result.response_time:.2f} seconds")
        print()
    
    # Get proxy stats
    stats = checker.get_proxy_stats()
    print(f"Proxy stats: {stats}")


if __name__ == "__main__":
    main()
