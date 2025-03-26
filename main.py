import json
import sys
import argparse
from datetime import datetime
import requests
import time
import concurrent.futures
import logging
from colorama import init, Fore, Style
from typing import List, Tuple, Dict, Optional, Set, Any
import csv  # Import the csv module

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class RateLimitExceeded(Exception):
    """Custom exception for rate limiting"""
    pass

class RateLimiter:
    """More sophisticated rate limiter using a token bucket."""
    def __init__(self, rate: int, capacity: int):
        self.rate = rate  # Number of requests per second
        self.capacity = capacity  # Maximum number of tokens
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, tokens=1) -> None:
        """Consume a specified number of tokens. Sleeps if necessary."""
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self.last_update = now

        if self.tokens < tokens:
            sleep_time = tokens / self.rate - delta
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.tokens = 0
        else:
            self.tokens -= tokens

# Initialize a global rate limiter (can be adjusted)
rate_limiter = RateLimiter(rate=0.5, capacity=2)  # Allow 0.5 requests per second, burst of 2

def rate_limit(func):
    """Decorator using the RateLimiter class."""
    def wrapper(*args, **kwargs):
        rate_limiter.consume()
        return func(*args, **kwargs)
    return wrapper

# Add a global session for requests with connection pooling
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
})

def fetch_url(url: str, method: str = "GET", params: Optional[Dict] = None, data: Optional[Dict] = None, headers: Optional[Dict] = None, timeout: int = 10) -> requests.Response:
    """Wrapper around requests to handle exceptions and logging."""
    try:
        response = session.request(method, url, params=params, data=data, headers=headers, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {url}: {e}")
        raise

@rate_limit
def check_signup_api(email):
    """Check using Google Signup API"""
    signup_url = "https://accounts.google.com/_/signup/validateemail"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "X-Same-Domain": "1",
        "Google-Accounts-XSRF": "1",
        "Origin": "https://accounts.google.com",
        "Referer": "https://accounts.google.com/signup",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    }
    
    username = email.replace("@gmail.com", "")
    payload = {
        "continuation": "1",
        "flowName": "GlifWebSignIn",
        "flowEntry": "SignUp",
        "checkConnection": "youtube:1",
        "checkedDomains": "youtube",
        "username": username,
        "hl": "en",
        "dsh": "S-1643533463:1703554785574582",  # This might need to be updated
        "sessionId": f"{int(time.time() * 1000)}",
        "_reqid": str(int(time.time() * 1000))
    }

    try:
        session = requests.Session()
        # First get the signup page to get necessary cookies
        session.get("https://accounts.google.com/signup")
        
        response = session.post(signup_url, headers=headers, data=payload)
        
        if response.status_code == 200:
            if "That username is taken" in response.text or "username unavailable" in response.text.lower():
                return (True, "Email exists (confirmed via signup API)")
            elif "username available" in response.text.lower():
                return (False, "Email does not exist (confirmed via signup API)")
            
            # Log the response for debugging
            logging.debug(f"Response text: {response.text[:200]}...")
        else:
            logging.warning(f"Unexpected status code: {response.status_code}")
            
        return (None, "Signup API check inconclusive")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {str(e)}")
        return (None, f"Error in signup API: {str(e)}")
    
def alternative_check(email):
    """Alternative method to check email existence"""
    try:
        username = email.replace("@gmail.com", "")
        
        # Basic validation
        if len(username) < 6 or len(username) > 30:
            return (True, "Invalid length")
            
        if not username[0].isalpha():
            return (True, "Must start with letter")
            
        if not all(c.isalnum() or c in '.-_' for c in username):
            return (True, "Invalid characters")
            
        # Add additional checks here
        
        return (None, "Could not determine status")
        
    except Exception as e:
        logging.error(f"Error in alternative check: {str(e)}")
        return (None, "Error checking email")
    
@rate_limit
def check_gmail_api(email: str) -> Tuple[Optional[bool], str]:
    """Check using Gmail's API"""
    gmail_check_url = "https://mail.google.com/mail/gxlu"
    params = {
        "_reqid": "1",
        "rt": "j",
        "at": "AF6bupMBBpWxA8h1VQ",  # This token might expire or be specific to sessions
    }

    try:
        response = fetch_url(gmail_check_url, params=params)

        if response.status_code == 200:
            if "suspicious" in response.text.lower():
                return (None, "Gmail API reports suspicious activity")
            return (True, "Email likely exists (Gmail API)")

        return (None, f"Gmail API check inconclusive - Status Code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        return (None, f"Error in Gmail API: {str(e)}")

@rate_limit
def check_google_apis(email: str) -> Tuple[Optional[bool], str]:
    """
    Check email existence using Google's APIs
    Returns: (bool, str) - (exists, details)
    """
    # Method 1: Google Signup API check
    signup_result = check_signup_api(email)
    if signup_result[0] is not None:  # If we got a definitive result
        return signup_result

    # Method 2: Gmail API check
    gmail_result = check_gmail_api(email)
    return gmail_result

def verify_email_existence(email: str) -> Tuple[Optional[bool], str]:
    """
    Comprehensive email verification using multiple methods
    Returns: (bool, str) - (exists, details)
    """
    # First try Google APIs
    google_result = check_google_apis(email)
    if google_result[0] is not None:  # If we got a definitive result
        return google_result

    # If Google APIs were inconclusive, try basic validation
    if '@gmail.com' in email.lower():
        username = email.split('@')[0]
        if not (6 <= len(username) <= 30):
            return (False, "Invalid Gmail username length")

        if not username[0].isalpha():
            return (False, "Gmail username must start with a letter")

        if not all(c.isalnum() or c in '.-_' for c in username):
            return (False, "Invalid characters in Gmail username")

    return (None, "Verification inconclusive")

def check_email_availability(email: str) -> Tuple[str, Optional[bool], str]:
    """
    Main function to check email availability
    Returns: (email, status, details)
    status: True if available, False if taken, None if uncertain
    """
    existence_result = verify_email_existence(email)

    if existence_result[0] is True:
        return (email, False, "Email is taken")
    elif existence_result[0] is False:
        return (email, True, "Email is available")
    else:
        return (email, None, existence_result[1])

def verify_available_emails(available_emails: List[str], max_workers: int = 3) -> List[Tuple[str, Optional[bool], str]]:
    """
    Perform detailed verification of supposedly available emails
    """
    print(f"\n{Fore.CYAN}Performing detailed verification of available emails...{Style.RESET_ALL}")

    verified_results: List[Tuple[str, Optional[bool], str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_email = {
            executor.submit(check_email_availability, email): email
            for email in available_emails
        }

        for future in concurrent.futures.as_completed(future_to_email):
            email = future_to_email[future]
            try:
                result = future.result()
                verified_results.append(result)

                # Color-coded output
                status_color = Fore.GREEN if result[1] is True else Fore.RED if result[1] is False else Fore.YELLOW
                status = "AVAILABLE" if result[1] is True else "TAKEN" if result[1] is False else "UNCERTAIN"

                print(f"{status_color}{email}: {status} - {result[2]}{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}Error verifying {email}: {str(e)}{Style.RESET_ALL}")

    return verified_results

def validate_user_data(user_data: Dict[str, Any]) -> None:
    """Validate required fields in user data"""
    required_fields = {
        'name': ['first_name', 'last_name']
    }

    if not user_data:
        raise ValueError("User data is empty")

    if 'name' not in user_data:
        raise ValueError("Missing 'name' field in user data")

    for field, subfields in required_fields.items():
        for subfield in subfields:
            if subfield not in user_data[field]:
                raise ValueError(f"Missing required field: {field}.{subfield}")

def save_results_to_file(filename: str, results: List[Tuple[str, Optional[bool], str]], verified_results: Optional[List[Tuple[str, Optional[bool], str]]] = None) -> None:
    """
    Save results to file with detailed formatting
    """
    with open(filename, 'w') as f:
        f.write("=== Gmail Address Availability Report ===\n\n")

        # Write timestamp
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Write verified results if available
        if verified_results:
            f.write("=== Verified Available Addresses ===\n")
            available = [r[0] for r in verified_results if r[1] is True]
            for email in available:
                f.write(f"✓ {email}\n")

            f.write("\n=== Possibly Available (Uncertain) ===\n")
            uncertain = [r[0] for r in verified_results if r[1] is None]
            for email in uncertain:
                f.write(f"? {email}\n")

            f.write("\n=== Confirmed Taken Addresses ===\n")
            taken = [r[0] for r in verified_results if r[1] is False]
            for email in taken:
                f.write(f"✗ {email}\n")

        # Write initial results (before detailed verification)
        f.write("\n=== Initial Check Results ===\n")
        available_initial = [r[0] for r in results if r[1] is True]
        uncertain_initial = [r[0] for r in results if r[1] is None]
        taken_initial = [r[0] for r in results if r[1] is False]

        f.write("\n=== Initially Available Addresses ===\n")
        for email in available_initial:
            f.write(f"+ {email}\n")

        f.write("\n=== Initially Uncertain Addresses ===\n")
        for email in uncertain_initial:
            f.write(f"~ {email}\n")

        f.write("\n=== Initially Taken Addresses ===\n")
        for email in taken_initial:
            f.write(f"- {email}\n")

        # Write statistics
        f.write("\n=== Statistics ===\n")
        if verified_results:
            f.write(f"Total verified available: {len(available)}\n")
            f.write(f"Total uncertain after verification: {len(uncertain)}\n")
            f.write(f"Total confirmed taken: {len(taken)}\n")
        f.write(f"Total initially available: {len(available_initial)}\n")
        f.write(f"Total initially uncertain: {len(uncertain_initial)}\n")
        f.write(f"Total initially taken: {len(taken_initial)}\n")

def load_user_data(json_file: str) -> List[Dict[str, Any]]:
    """
    Load and validate user data from JSON file
    """
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        users = data.get('users', [])
        if not users:
            raise ValueError("No users found in JSON file")

        # Validate each user's data
        for user in users:
            validate_user_data(user)

        return users
    except FileNotFoundError:
        print(f"{Fore.RED}Error: JSON file '{json_file}' not found{Style.RESET_ALL}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Fore.RED}Error: Invalid JSON format in '{json_file}'{Style.RESET_ALL}")
        sys.exit(1)
    except ValueError as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def generate_gmail_variations(user_data: Dict[str, Any]) -> List[str]:
    """
    Generate possible Gmail address variations for a user
    Args:
        user_data (dict): Dictionary containing user information
            Required keys:
            - name: dict with first_name and last_name
            Optional keys:
            - year_of_birth: int
            - date_of_birth: str (DD-MM-YYYY)
            - nicknames: list[str]
    """
    variations: Set[str] = set()

    try:
        first_name = user_data['name']['first_name'].lower().strip()
        last_name = user_data['name']['last_name'].lower().strip()
        birth_year = user_data.get('year_of_birth')
        birth_date = user_data.get('date_of_birth')
        nicknames = user_data.get('nicknames', [])

        # Basic patterns with real name
        name_patterns = [
            f"{first_name}.{last_name}@gmail.com",
            f"{last_name}_{first_name}@gmail.com",
            f"{first_name}{last_name}@gmail.com",
            f"{last_name}.{first_name}@gmail.com",
            f"{first_name[0]}{last_name}@gmail.com",
            f"{first_name}_{last_name}@gmail.com",
            f"{last_name}{first_name[0]}@gmail.com",
        ]
        variations.update(name_patterns)

        # Add patterns with nicknames
        for nickname in nicknames:
            nickname = nickname.lower().strip()
            nickname_patterns = [
                f"{nickname}.{last_name}@gmail.com",
                f"{last_name}_{nickname}@gmail.com",
                f"{nickname}{last_name}@gmail.com",
                f"{last_name}.{nickname}@gmail.com",
                f"{nickname}@gmail.com"
            ]
            variations.update(nickname_patterns)

        if birth_year:
            # Year variations
            short_year = str(birth_year)[-2:]
            year_patterns = [
                f"{first_name}.{last_name}{short_year}@gmail.com",
                f"{last_name}{first_name}{short_year}@gmail.com",
                f"{first_name}{last_name}.{short_year}@gmail.com",
                f"{first_name}.{last_name}.{birth_year}@gmail.com",
                f"{last_name}{first_name}.{birth_year}@gmail.com",
            ]
            variations.update(year_patterns)

            # Add year variations for nicknames
            for nickname in nicknames:
                nickname = nickname.lower().strip()
                nickname_year_patterns = [
                    f"{nickname}.{last_name}{short_year}@gmail.com",
                    f"{nickname}{last_name}{short_year}@gmail.com",
                    f"{nickname}.{last_name}.{birth_year}@gmail.com",
                ]
                variations.update(nickname_year_patterns)

        if birth_date:
            try:
                date_obj = datetime.strptime(birth_date, '%d-%m-%Y')
                ddmmyy = date_obj.strftime('%d%m%y')
                ddmmyyyy = date_obj.strftime('%d%m%Y')

                # Date variations
                date_patterns = [
                    f"{first_name}{last_name}{ddmmyy}@gmail.com",
                    f"{first_name}.{last_name}{ddmmyyyy}@gmail.com",
                    f"{last_name}_{first_name}{ddmmyy}@gmail.com",
                ]
                variations.update(date_patterns)

                # Add date variations for nicknames
                for nickname in nicknames:
                    nickname = nickname.lower().strip()
                    nickname_date_patterns = [
                        f"{nickname}{last_name}{ddmmyy}@gmail.com",
                        f"{nickname}.{last_name}{ddmmyyyy}@gmail.com",
                    ]
                    variations.update(nickname_date_patterns)

            except ValueError:
                logging.warning(f"Invalid date format for {first_name} {last_name}. Skipping date-based variations.")

        return sorted(list(variations))

    except KeyError as e:
        logging.error(f"Missing required field in user data: {str(e)}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Generate and check availability of Gmail addresses from JSON file')
    parser.add_argument('json_file', type=str, help='Path to JSON file containing user information')
    parser.add_argument('--output', '-o', type=str, help='Output file to save results')
    parser.add_argument('--check-availability', '-c', action='store_true', help='Check email availability')
    parser.add_argument('--max-workers', '-w', type=int, default=3, help='Maximum number of concurrent checks')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    
    
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load user data from JSON
        users = load_user_data(args.json_file)
        
        all_variations = []
        for user in users:
            variations = generate_gmail_variations(user)
            all_variations.extend(variations)
            print(f"\nGenerated {len(variations)} variations for {user['name']['first_name']} {user['name']['last_name']}")
        
        if args.check_availability:
            print(f"\nChecking availability for {len(all_variations)} email addresses...")
            print("This may take a few minutes. Please wait...\n")
            
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                future_to_email = {executor.submit(check_email_availability, email): email 
                                for email in all_variations}
                
                for future in concurrent.futures.as_completed(future_to_email):
                    email = future_to_email[future]
                    try:
                        result = future.result()
                        results.append(result)
                        status_color = Fore.GREEN if result[1] else Fore.RED if result[1] is False else Fore.YELLOW
                        print(f"{status_color}{result[0]}: {result[2]}{Style.RESET_ALL}")
                    except Exception as e:
                        logging.error(f"Error checking {email}: {str(e)}")
                        print(f"{Fore.RED}Error checking {email}: {str(e)}{Style.RESET_ALL}")
            
            # Sort results by availability
            available = [r[0] for r in results if r[1] is True]
            taken = [r[0] for r in results if r[1] is False]
            error = [r[0] for r in results if r[1] is None]
            
            if available:
                print(f"\n{Fore.CYAN}Found {len(available)} potentially available addresses.{Style.RESET_ALL}")
                verified_results = verify_available_emails(available, args.max_workers)
                
                if args.output:
                    save_results_to_file(args.output, results, verified_results)
                    print(f"\nDetailed results saved to {args.output}")
                
                # Print final summary
                truly_available = len([r for r in verified_results if r[1] is True])
                uncertain = len([r for r in verified_results if r[1] is None])
                actually_taken = len([r for r in verified_results if r[1] is False])
                
                print(f"\nFinal Verification Summary:")
                print(f"{Fore.GREEN}Confirmed Available: {truly_available}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Status Uncertain: {uncertain}{Style.RESET_ALL}")
                print(f"{Fore.RED}Actually Taken: {actually_taken}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}No available email addresses found.{Style.RESET_ALL}")
                
                if args.output:
                    save_results_to_file(args.output, results)
                    print(f"\nResults saved to {args.output}")
        else:
            if args.output:
                with open(args.output, 'w') as f:
                    for email in all_variations:
                        f.write(f"{email}\n")
                print(f"\nGenerated {len(all_variations)} total email variations and saved to {args.output}")
            else:
                print("\nPotential Gmail addresses:")
                for email in all_variations:
                    print(email)
                print(f"\nTotal variations generated: {len(all_variations)}")
    
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"{Fore.RED}An error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()