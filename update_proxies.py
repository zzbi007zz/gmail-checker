#!/usr/bin/env python3
"""
Proxy List Updater

This script fetches free proxies from various public APIs and updates the proxy list file.
"""

import requests
import json
import argparse
import logging
import time
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProxyFetcher:
    """Class for fetching proxies from various sources."""
    
    def __init__(self):
        self.proxies = []
    
    def fetch_from_geonode(self, limit=20):
        """Fetch proxies from GeoNode API."""
        try:
            url = f"https://proxylist.geonode.com/api/proxy-list?limit={limit}&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols=http%2Chttps"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if "data" in data and isinstance(data["data"], list):
                for item in data["data"]:
                    if "ip" in item and "port" in item and "protocols" in item:
                        for protocol in item["protocols"]:
                            proxy = f"{protocol}://{item['ip']}:{item['port']}"
                            self.proxies.append(proxy)
                
                logger.info(f"Fetched {len(self.proxies)} proxies from GeoNode")
            else:
                logger.warning("Unexpected response format from GeoNode")
        
        except Exception as e:
            logger.error(f"Error fetching proxies from GeoNode: {str(e)}")
    
    def fetch_from_proxyscrape(self):
        """Fetch proxies from ProxyScrape API."""
        try:
            url = "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&simplified=true"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Response is plain text with one proxy per line
            lines = response.text.strip().split('\n')
            for line in lines:
                if ':' in line:
                    proxy = f"http://{line.strip()}"
                    self.proxies.append(proxy)
            
            logger.info(f"Fetched {len(lines)} proxies from ProxyScrape")
        
        except Exception as e:
            logger.error(f"Error fetching proxies from ProxyScrape: {str(e)}")
    
    def fetch_from_free_proxy_list(self):
        """Fetch proxies from Free-Proxy-List.net."""
        try:
            url = "https://www.free-proxy-list.net/"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # This site returns HTML, so we need to parse it
            # This is a simplified example and may need adjustment
            import re
            pattern = r'<td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>'
            matches = re.findall(pattern, response.text)
            
            for ip, port in matches:
                proxy = f"http://{ip}:{port}"
                self.proxies.append(proxy)
            
            logger.info(f"Fetched {len(matches)} proxies from Free-Proxy-List")
        
        except Exception as e:
            logger.error(f"Error fetching proxies from Free-Proxy-List: {str(e)}")
    
    def remove_duplicates(self):
        """Remove duplicate proxies."""
        self.proxies = list(set(self.proxies))
        logger.info(f"Removed duplicates, {len(self.proxies)} unique proxies remaining")
    
    def save_to_file(self, file_path):
        """Save proxies to a file."""
        try:
            with open(file_path, 'w') as f:
                f.write(f"# Free proxies fetched from multiple sources\n")
                f.write(f"# Format: protocol://IP:PORT\n")
                f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Note: These proxies may not always be available as they change frequently\n\n")
                
                for proxy in self.proxies:
                    f.write(f"{proxy}\n")
                
                f.write("\n# You can find more free proxies at:\n")
                f.write("# - https://proxylist.geonode.com/\n")
                f.write("# - https://www.proxyscrape.com/\n")
                f.write("# - https://free-proxy-list.net/\n")
                f.write("# - https://www.sslproxies.org/\n")
            
            logger.info(f"Saved {len(self.proxies)} proxies to {file_path}")
        
        except Exception as e:
            logger.error(f"Error saving proxies to file: {str(e)}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Fetch and update proxy list")
    parser.add_argument("-o", "--output", default="sample_proxies.txt", help="Output file path")
    parser.add_argument("-l", "--limit", type=int, default=20, help="Number of proxies to fetch from each source")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create fetcher
    fetcher = ProxyFetcher()
    
    # Fetch proxies from various sources
    logger.info("Fetching proxies from GeoNode...")
    fetcher.fetch_from_geonode(limit=args.limit)
    
    logger.info("Fetching proxies from ProxyScrape...")
    fetcher.fetch_from_proxyscrape()
    
    logger.info("Fetching proxies from Free-Proxy-List...")
    fetcher.fetch_from_free_proxy_list()
    
    # Remove duplicates
    fetcher.remove_duplicates()
    
    # Save to file
    fetcher.save_to_file(args.output)
    
    logger.info("Proxy list updated successfully")


if __name__ == "__main__":
    main()
