#!/usr/bin/env python3
"""
Proxy Tester

This script tests the proxies in a file to check if they are working.
"""

import requests
import argparse
import logging
import time
import concurrent.futures
from typing import Dict, List, Tuple
import json
import os
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProxyTester:
    """Class for testing proxies."""
    
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.test_urls = [
            "https://httpbin.org/ip",
            "https://api.ipify.org",
            "https://www.google.com",
        ]
    
    def load_proxies_from_file(self, file_path: str) -> List[str]:
        """Load proxies from a file."""
        if not os.path.exists(file_path):
            logger.error(f"Proxy file not found: {file_path}")
            return []
        
        proxies = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Add protocol if not present
                        if not line.startswith(('http://', 'https://', 'socks://')):
                            line = f"http://{line}"
                        proxies.append(line)
            
            logger.info(f"Loaded {len(proxies)} proxies from {file_path}")
            return proxies
        
        except Exception as e:
            logger.error(f"Error loading proxies from file: {str(e)}")
            return []
    
    def test_proxy(self, proxy: str) -> Tuple[str, bool, float, str]:
        """Test a single proxy."""
        start_time = time.time()
        
        # Parse the proxy URL
        parsed = urlparse(proxy)
        protocol = parsed.scheme
        
        # Set up the proxy dict for requests
        proxies = {
            protocol: proxy
        }
        
        # Try each test URL
        for url in self.test_urls:
            try:
                response = requests.get(
                    url,
                    proxies=proxies,
                    timeout=self.timeout,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                )
                
                if response.status_code == 200:
                    response_time = time.time() - start_time
                    return proxy, True, response_time, "Success"
            
            except requests.exceptions.ConnectTimeout:
                continue
            except requests.exceptions.ProxyError:
                return proxy, False, 0, "Proxy error"
            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                return proxy, False, 0, str(e)
        
        return proxy, False, 0, "All test URLs failed"
    
    def test_proxies(self, proxies: List[str], max_workers: int = 10) -> List[Dict]:
        """Test multiple proxies in parallel."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {executor.submit(self.test_proxy, proxy): proxy for proxy in proxies}
            
            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    proxy, success, response_time, message = future.result()
                    
                    result = {
                        "proxy": proxy,
                        "success": success,
                        "response_time": response_time,
                        "message": message
                    }
                    
                    results.append(result)
                    
                    if success:
                        logger.info(f"Proxy {proxy} is working (response time: {response_time:.2f}s)")
                    else:
                        logger.info(f"Proxy {proxy} failed: {message}")
                
                except Exception as e:
                    logger.error(f"Error testing proxy {proxy}: {str(e)}")
                    results.append({
                        "proxy": proxy,
                        "success": False,
                        "response_time": 0,
                        "message": str(e)
                    })
        
        return results
    
    def save_results(self, results: List[Dict], output_file: str) -> None:
        """Save test results to a file."""
        try:
            # Sort results by success and response time
            results.sort(key=lambda x: (not x["success"], x.get("response_time", float('inf'))))
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Results saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
    
    def save_working_proxies(self, results: List[Dict], output_file: str) -> None:
        """Save only working proxies to a file."""
        try:
            # Filter and sort working proxies by response time
            working_proxies = [r for r in results if r["success"]]
            working_proxies.sort(key=lambda x: x.get("response_time", float('inf')))
            
            with open(output_file, 'w') as f:
                f.write(f"# Working proxies tested on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: protocol://IP:PORT\n")
                f.write(f"# Total working proxies: {len(working_proxies)}\n\n")
                
                for result in working_proxies:
                    f.write(f"{result['proxy']} # Response time: {result['response_time']:.2f}s\n")
            
            logger.info(f"Working proxies saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error saving working proxies: {str(e)}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Test proxies in a file")
    parser.add_argument("-i", "--input", default="sample_proxies.txt", help="Input proxy file path")
    parser.add_argument("-o", "--output", default="working_proxies.txt", help="Output file for working proxies")
    parser.add_argument("-r", "--results", default="proxy_test_results.json", help="Output file for test results")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds for each proxy test")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of worker threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create tester
    tester = ProxyTester(timeout=args.timeout)
    
    # Load proxies
    proxies = tester.load_proxies_from_file(args.input)
    
    if not proxies:
        logger.error("No proxies to test")
        return
    
    # Test proxies
    logger.info(f"Testing {len(proxies)} proxies with {args.workers} workers...")
    results = tester.test_proxies(proxies, max_workers=args.workers)
    
    # Count working proxies
    working_count = sum(1 for r in results if r["success"])
    logger.info(f"Test completed: {working_count} out of {len(results)} proxies are working")
    
    # Save results
    tester.save_results(results, args.results)
    
    # Save working proxies
    tester.save_working_proxies(results, args.output)


if __name__ == "__main__":
    main()
