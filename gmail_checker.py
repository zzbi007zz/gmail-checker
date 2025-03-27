#!/usr/bin/env python3
"""
Gmail Registration Checker

This module provides functionality to check if Gmail addresses are registered
using free proxies to prevent IP blocking.

Design Patterns Used:
- Strategy Pattern: For different email verification methods
- Factory Pattern: For creating proxy objects
- Singleton Pattern: For the proxy manager
- Observer Pattern: For monitoring proxy health
"""

import smtplib
import socket
import time
import random
import logging
import requests
import abc
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import concurrent.futures
import re
import json
import os
from urllib.parse import urlparse
import functools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ---- Rate Limiter ----

class RateLimiter:
    """Rate limiter using a token bucket algorithm."""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # Number of requests per second
        self.capacity = capacity  # Maximum number of tokens
        self.tokens = capacity
        self.last_update = time.time()
    
    def consume(self, tokens: int = 1) -> None:
        """Consume a specified number of tokens. Sleeps if necessary."""
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self.last_update = now
        
        if self.tokens < tokens:
            sleep_time = (tokens - self.tokens) / self.rate
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.tokens = 0
        else:
            self.tokens -= tokens


# Initialize a global rate limiter (can be adjusted)
rate_limiter = RateLimiter(rate=0.5, capacity=2)  # Allow 0.5 requests per second, burst of 2


def rate_limit(func):
    """Decorator using the RateLimiter class."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        rate_limiter.consume()
        return func(*args, **kwargs)
    return wrapper


# ---- Domain Models ----

class ProxyStatus(Enum):
    """Enum representing the status of a proxy."""
    AVAILABLE = "available"
    IN_USE = "in_use"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class Proxy:
    """Class representing a proxy server."""
    host: str
    port: int
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None
    status: ProxyStatus = ProxyStatus.AVAILABLE
    fail_count: int = 0
    last_used: float = 0
    response_time: float = 0

    @property
    def address(self) -> str:
        """Get the full proxy address."""
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def auth_address(self) -> str:
        """Get the full proxy address with authentication if available."""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return self.address

    def as_dict(self) -> Dict:
        """Convert proxy to dictionary format for requests library."""
        proxy_dict = {
            self.protocol: self.address
        }
        return proxy_dict


class EmailVerificationResult(Enum):
    """Enum representing the result of an email verification."""
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class VerificationResult:
    """Class representing the result of an email verification."""
    email: str
    result: EmailVerificationResult
    message: str
    proxy_used: Optional[Proxy] = None
    response_time: float = 0


# ---- Observer Pattern ----

class ProxyObserver(abc.ABC):
    """Abstract base class for proxy observers."""
    
    @abc.abstractmethod
    def update(self, proxy: Proxy, event_type: str) -> None:
        """Update method called when a proxy's status changes."""
        pass


class ProxySubject(abc.ABC):
    """Abstract base class for proxy subjects."""
    
    @abc.abstractmethod
    def attach(self, observer: ProxyObserver) -> None:
        """Attach an observer to this subject."""
        pass
    
    @abc.abstractmethod
    def detach(self, observer: ProxyObserver) -> None:
        """Detach an observer from this subject."""
        pass
    
    @abc.abstractmethod
    def notify(self, proxy: Proxy, event_type: str) -> None:
        """Notify all observers about an event."""
        pass


# ---- Strategy Pattern ----

class EmailVerificationStrategy(abc.ABC):
    """Abstract base class for email verification strategies."""
    
    @abc.abstractmethod
    def verify(self, email: str, proxy: Optional[Proxy] = None) -> VerificationResult:
        """Verify if an email address is valid."""
        pass


class SmtpVerificationStrategy(EmailVerificationStrategy):
    """Email verification strategy using SMTP."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def verify(self, email: str, proxy: Optional[Proxy] = None) -> VerificationResult:
        """
        Verify if an email address is valid using SMTP.
        
        This method connects to Gmail's SMTP server and checks if the email exists.
        """
        if not self._is_valid_email_format(email):
            return VerificationResult(
                email=email,
                result=EmailVerificationResult.INVALID,
                message="Invalid email format"
            )
        
        start_time = time.time()
        
        try:
            # Set up socket with proxy if provided
            if proxy:
                # For SMTP, we'd need to implement a SOCKS proxy connection
                # This is simplified for demonstration purposes
                logger.info(f"Using proxy {proxy.address} for SMTP verification")
            
            # Connect to Gmail's SMTP server
            server = smtplib.SMTP('smtp.gmail.com', 587, timeout=self.timeout)
            server.ehlo()
            server.starttls()
            server.ehlo()
            
            # Try to verify the email
            status_code, response = server.verify(email)
            server.quit()
            
            response_time = time.time() - start_time
            
            if status_code == 250:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.VALID,
                    message="Email exists",
                    proxy_used=proxy,
                    response_time=response_time
                )
            elif status_code == 550:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Email does not exist",
                    proxy_used=proxy,
                    response_time=response_time
                )
            else:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.UNKNOWN,
                    message=f"Unexpected response: {response}",
                    proxy_used=proxy,
                    response_time=response_time
                )
        
        except (socket.timeout, smtplib.SMTPServerDisconnected) as e:
            response_time = time.time() - start_time
            return VerificationResult(
                email=email,
                result=EmailVerificationResult.ERROR,
                message=f"Connection timeout or disconnected: {str(e)}",
                proxy_used=proxy,
                response_time=response_time
            )
        except smtplib.SMTPResponseException as e:
            response_time = time.time() - start_time
            if e.smtp_code == 550:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Email does not exist",
                    proxy_used=proxy,
                    response_time=response_time
                )
            else:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.ERROR,
                    message=f"SMTP error: {e.smtp_code} {e.smtp_error}",
                    proxy_used=proxy,
                    response_time=response_time
                )
        except Exception as e:
            response_time = time.time() - start_time
            return VerificationResult(
                email=email,
                result=EmailVerificationResult.ERROR,
                message=f"Error: {str(e)}",
                proxy_used=proxy,
                response_time=response_time
            )
    
    def _is_valid_email_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
        return bool(re.match(pattern, email))


class HttpVerificationStrategy(EmailVerificationStrategy):
    """Email verification strategy using HTTP requests to check if Gmail addresses are registered."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def verify(self, email: str, proxy: Optional[Proxy] = None) -> VerificationResult:
        """
        Verify if a Gmail address is registered using Google's signup API.
        
        This method attempts to determine if an email address is already registered
        with Gmail by checking Google's signup API.
        """
        start_time = time.time()
        
        # Check if the email has a valid format
        if not self._is_valid_email_format(email):
            return VerificationResult(
                email=email,
                result=EmailVerificationResult.INVALID,
                message="Invalid email format",
                proxy_used=proxy,
                response_time=time.time() - start_time
            )
        
        # For Gmail addresses, check if the account exists
        if email.lower().endswith('@gmail.com'):
            # Extract the username part
            username = email.lower().split('@')[0]
            
            # Check Gmail-specific rules
            if len(username) < 6 or len(username) > 30:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Gmail username must be between 6-30 characters",
                    proxy_used=proxy,
                    response_time=time.time() - start_time
                )
            
            # Check for valid characters in Gmail username
            if not re.match(r'^[a-z0-9.]+$', username):
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Gmail username can only contain letters, numbers, and periods",
                    proxy_used=proxy,
                    response_time=time.time() - start_time
                )
            
            # Check for consecutive periods
            if '..' in username:
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Gmail username cannot contain consecutive periods",
                    proxy_used=proxy,
                    response_time=time.time() - start_time
                )
            
            # Check if username starts or ends with a period
            if username.startswith('.') or username.endswith('.'):
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.INVALID,
                    message="Gmail username cannot start or end with a period",
                    proxy_used=proxy,
                    response_time=time.time() - start_time
                )
            
            # If all format checks pass, check if the account exists using Google's signup API
            try:
                proxies = None
                if proxy:
                    proxies = proxy.as_dict()
                    logger.info(f"Using proxy {proxy.address} for HTTP verification")
                
                result = self._check_signup_api(email, proxies)
                response_time = time.time() - start_time
                
                if result[0] is True:  # Email exists
                    return VerificationResult(
                        email=email,
                        result=EmailVerificationResult.VALID,
                        message=result[1],
                        proxy_used=proxy,
                        response_time=response_time
                    )
                elif result[0] is False:  # Email doesn't exist
                    return VerificationResult(
                        email=email,
                        result=EmailVerificationResult.INVALID,
                        message=result[1],
                        proxy_used=proxy,
                        response_time=response_time
                    )
                else:  # Couldn't determine
                    return VerificationResult(
                        email=email,
                        result=EmailVerificationResult.UNKNOWN,
                        message=result[1],
                        proxy_used=proxy,
                        response_time=response_time
                    )
            except Exception as e:
                response_time = time.time() - start_time
                logger.error(f"Error checking email existence: {str(e)}")
                return VerificationResult(
                    email=email,
                    result=EmailVerificationResult.ERROR,
                    message=f"Error checking email: {str(e)}",
                    proxy_used=proxy,
                    response_time=response_time
                )
        
        # For non-Gmail addresses
        return VerificationResult(
            email=email,
            result=EmailVerificationResult.UNKNOWN,
            message="Only Gmail addresses are supported by this tool",
            proxy_used=proxy,
            response_time=time.time() - start_time
        )
    
    def _is_valid_email_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
        return bool(re.match(pattern, email))
        
    @rate_limit
    def _check_signup_api(self, email: str, proxies: Optional[Dict] = None) -> Tuple[Optional[bool], str]:
        """Check using Google Signup API with rate limiting."""
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
            session.get("https://accounts.google.com/signup", proxies=proxies, timeout=self.timeout)
            
            response = session.post(signup_url, headers=headers, data=payload, proxies=proxies, timeout=self.timeout)
            
            if response.status_code == 200:
                if "That username is taken" in response.text or "username unavailable" in response.text.lower():
                    return (True, "Email exists (confirmed via signup API)")
                elif "username available" in response.text.lower():
                    return (False, "Email does not exist (confirmed via signup API)")
                
                # Log the response for debugging
                logger.debug(f"Response text: {response.text[:200]}...")
            else:
                logger.warning(f"Unexpected status code: {response.status_code}")
                
            return (None, "Signup API check inconclusive")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return (None, f"Error in signup API: {str(e)}")


# ---- Factory Pattern ----

class ProxyFactory(abc.ABC):
    """Abstract factory for creating proxy objects."""
    
    @abc.abstractmethod
    def create_proxy(self, proxy_data: Dict) -> Proxy:
        """Create a proxy object from the provided data."""
        pass


class HttpProxyFactory(ProxyFactory):
    """Factory for creating HTTP proxies."""
    
    def create_proxy(self, proxy_data: Dict) -> Proxy:
        """Create an HTTP proxy from the provided data."""
        return Proxy(
            host=proxy_data.get("host", ""),
            port=int(proxy_data.get("port", 0)),
            protocol="http",
            username=proxy_data.get("username"),
            password=proxy_data.get("password")
        )


class HttpsProxyFactory(ProxyFactory):
    """Factory for creating HTTPS proxies."""
    
    def create_proxy(self, proxy_data: Dict) -> Proxy:
        """Create an HTTPS proxy from the provided data."""
        return Proxy(
            host=proxy_data.get("host", ""),
            port=int(proxy_data.get("port", 0)),
            protocol="https",
            username=proxy_data.get("username"),
            password=proxy_data.get("password")
        )


class SocksProxyFactory(ProxyFactory):
    """Factory for creating SOCKS proxies."""
    
    def create_proxy(self, proxy_data: Dict) -> Proxy:
        """Create a SOCKS proxy from the provided data."""
        return Proxy(
            host=proxy_data.get("host", ""),
            port=int(proxy_data.get("port", 0)),
            protocol="socks5",
            username=proxy_data.get("username"),
            password=proxy_data.get("password")
        )


class ProxyFactoryProvider:
    """Provider for proxy factories based on protocol."""
    
    @staticmethod
    def get_factory(protocol: str) -> ProxyFactory:
        """Get the appropriate factory for the given protocol."""
        if protocol.lower() == "http":
            return HttpProxyFactory()
        elif protocol.lower() == "https":
            return HttpsProxyFactory()
        elif protocol.lower() in ("socks", "socks4", "socks5"):
            return SocksProxyFactory()
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")


# ---- Singleton Pattern ----

class ProxyManager(ProxySubject):
    """
    Singleton class for managing proxies.
    
    This class is responsible for:
    - Loading proxies from various sources
    - Managing proxy status
    - Rotating proxies for use
    - Monitoring proxy health
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ProxyManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._proxies: List[Proxy] = []
        self._observers: List[ProxyObserver] = []
        self._cooldown_period = 60  # seconds
        self._max_fails = 3
        self._initialized = True
    
    def attach(self, observer: ProxyObserver) -> None:
        """Attach an observer to this subject."""
        if observer not in self._observers:
            self._observers.append(observer)
    
    def detach(self, observer: ProxyObserver) -> None:
        """Detach an observer from this subject."""
        self._observers.remove(observer)
    
    def notify(self, proxy: Proxy, event_type: str) -> None:
        """Notify all observers about an event."""
        for observer in self._observers:
            observer.update(proxy, event_type)
    
    def load_proxies_from_api(self, api_url: str) -> None:
        """Load proxies from a public API."""
        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            
            # Parse the response based on the API format
            # This is a simplified example and may need adjustment
            proxy_data = response.json()
            
            if isinstance(proxy_data, list):
                for item in proxy_data:
                    self._add_proxy_from_data(item)
            elif isinstance(proxy_data, dict) and "data" in proxy_data:
                for item in proxy_data["data"]:
                    self._add_proxy_from_data(item)
            
            logger.info(f"Loaded {len(self._proxies)} proxies from API")
        
        except Exception as e:
            logger.error(f"Error loading proxies from API: {str(e)}")
    
    def load_proxies_from_file(self, file_path: str) -> None:
        """Load proxies from a file."""
        if not os.path.exists(file_path):
            logger.error(f"Proxy file not found: {file_path}")
            return
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Try to parse as JSON
            try:
                proxy_data = json.loads(content)
                if isinstance(proxy_data, list):
                    for item in proxy_data:
                        self._add_proxy_from_data(item)
                elif isinstance(proxy_data, dict) and "proxies" in proxy_data:
                    for item in proxy_data["proxies"]:
                        self._add_proxy_from_data(item)
            except json.JSONDecodeError:
                # Parse as plain text (one proxy per line)
                lines = content.strip().split('\n')
                for line in lines:
                    self._add_proxy_from_text(line)
            
            logger.info(f"Loaded {len(self._proxies)} proxies from file")
        
        except Exception as e:
            logger.error(f"Error loading proxies from file: {str(e)}")
    
    def _add_proxy_from_data(self, data: Dict) -> None:
        """Add a proxy from structured data."""
        try:
            # Extract protocol, host, port, etc. from the data
            protocol = data.get("protocol", "http")
            
            # Get the appropriate factory
            factory = ProxyFactoryProvider.get_factory(protocol)
            
            # Create the proxy
            proxy = factory.create_proxy(data)
            
            # Add to the list
            self._proxies.append(proxy)
        
        except Exception as e:
            logger.error(f"Error adding proxy from data: {str(e)}")
    
    def _add_proxy_from_text(self, text: str) -> None:
        """Add a proxy from a text line."""
        try:
            # Parse the text line
            # Format examples:
            # - 192.168.1.1:8080
            # - http://192.168.1.1:8080
            # - http://user:pass@192.168.1.1:8080
            
            # Remove whitespace
            text = text.strip()
            
            # Skip empty lines
            if not text:
                return
                
            # Skip comment lines
            if text.startswith('#'):
                return
            
            # Parse URL if it has a protocol
            if "://" in text:
                parsed = urlparse(text)
                protocol = parsed.scheme or "http"
                
                # Extract authentication if present
                username = None
                password = None
                if "@" in parsed.netloc:
                    auth, netloc = parsed.netloc.split("@", 1)
                    if ":" in auth:
                        username, password = auth.split(":", 1)
                else:
                    netloc = parsed.netloc
                
                # Extract host and port
                if ":" in netloc:
                    host, port_str = netloc.split(":", 1)
                    port = int(port_str)
                else:
                    host = netloc
                    port = 80 if protocol == "http" else 443
            
            # Parse IP:PORT format
            elif ":" in text:
                protocol = "http"
                host, port_str = text.split(":", 1)
                port = int(port_str)
                username = None
                password = None
            
            else:
                # Invalid format
                logger.warning(f"Invalid proxy format: {text}")
                return
            
            # Create proxy data
            proxy_data = {
                "host": host,
                "port": port,
                "username": username,
                "password": password
            }
            
            # Get the appropriate factory
            factory = ProxyFactoryProvider.get_factory(protocol)
            
            # Create the proxy
            proxy = factory.create_proxy(proxy_data)
            
            # Add to the list
            self._proxies.append(proxy)
        
        except Exception as e:
            logger.error(f"Error adding proxy from text: {str(e)}")
    
    def get_proxy(self) -> Optional[Proxy]:
        """Get an available proxy."""
        available_proxies = [
            p for p in self._proxies
            if p.status == ProxyStatus.AVAILABLE and
            (time.time() - p.last_used) > self._cooldown_period
        ]
        
        if not available_proxies:
            logger.warning("No available proxies")
            return None
        
        # Sort by response time (faster first)
        available_proxies.sort(key=lambda p: p.response_time)
        
        # Get a proxy
        proxy = available_proxies[0]
        
        # Update status
        proxy.status = ProxyStatus.IN_USE
        proxy.last_used = time.time()
        
        # Notify observers
        self.notify(proxy, "in_use")
        
        return proxy
    
    def release_proxy(self, proxy: Proxy, success: bool = True) -> None:
        """Release a proxy after use."""
        if proxy not in self._proxies:
            return
        
        if success:
            proxy.status = ProxyStatus.AVAILABLE
            proxy.fail_count = 0
            self.notify(proxy, "available")
        else:
            proxy.fail_count += 1
            if proxy.fail_count >= self._max_fails:
                proxy.status = ProxyStatus.FAILED
                self.notify(proxy, "failed")
            else:
                proxy.status = ProxyStatus.AVAILABLE
                self.notify(proxy, "available")
    
    def mark_proxy_blocked(self, proxy: Proxy) -> None:
        """Mark a proxy as blocked."""
        if proxy not in self._proxies:
            return
        
        proxy.status = ProxyStatus.BLOCKED
        self.notify(proxy, "blocked")
    
    def get_stats(self) -> Dict:
        """Get statistics about the proxies."""
        total = len(self._proxies)
        available = sum(1 for p in self._proxies if p.status == ProxyStatus.AVAILABLE)
        in_use = sum(1 for p in self._proxies if p.status == ProxyStatus.IN_USE)
        failed = sum(1 for p in self._proxies if p.status == ProxyStatus.FAILED)
        blocked = sum(1 for p in self._proxies if p.status == ProxyStatus.BLOCKED)
        
        return {
            "total": total,
            "available": available,
            "in_use": in_use,
            "failed": failed,
            "blocked": blocked
        }


# ---- Proxy Health Monitor ----

class ProxyHealthMonitor(ProxyObserver):
    """Observer for monitoring proxy health."""
    
    def __init__(self):
        self.stats = {
            "available": 0,
            "in_use": 0,
            "failed": 0,
            "blocked": 0
        }
    
    def update(self, proxy: Proxy, event_type: str) -> None:
        """Update method called when a proxy's status changes."""
        if event_type == "available":
            self.stats["available"] += 1
        elif event_type == "in_use":
            self.stats["in_use"] += 1
        elif event_type == "failed":
            self.stats["failed"] += 1
        elif event_type == "blocked":
            self.stats["blocked"] += 1
        
        logger.debug(f"Proxy {proxy.address} is now {event_type}")
        logger.debug(f"Proxy stats: {self.stats}")


# ---- Main Application ----

class GmailChecker:
    """Main class for checking Gmail registrations."""
    
    def __init__(self, verification_strategy: EmailVerificationStrategy = None):
        self.proxy_manager = ProxyManager()
        self.health_monitor = ProxyHealthMonitor()
        self.proxy_manager.attach(self.health_monitor)
        
        # Set default verification strategy if not provided
        self.verification_strategy = verification_strategy or HttpVerificationStrategy()
    
    def load_proxies(self, source: str) -> None:
        """Load proxies from the specified source."""
        if source.startswith("http"):
            self.proxy_manager.load_proxies_from_api(source)
        else:
            self.proxy_manager.load_proxies_from_file(source)
    
    def check_email(self, email: str) -> VerificationResult:
        """Check if an email is registered."""
        # Get a proxy
        proxy = self.proxy_manager.get_proxy()
        
        try:
            # Verify the email
            result = self.verification_strategy.verify(email, proxy)
            
            # Update proxy status based on the result
            if proxy:
                if result.result == EmailVerificationResult.ERROR:
                    self.proxy_manager.release_proxy(proxy, success=False)
                else:
                    self.proxy_manager.release_proxy(proxy, success=True)
            
            return result
        
        except Exception as e:
            logger.error(f"Error checking email: {str(e)}")
            
            # Release the proxy as failed
            if proxy:
                self.proxy_manager.release_proxy(proxy, success=False)
            
            # Return an error result
            return VerificationResult(
                email=email,
                result=EmailVerificationResult.ERROR,
                message=f"Error: {str(e)}"
            )
    
    def check_emails_batch(self, emails: List[str], max_workers: int = 5) -> List[VerificationResult]:
        """Check multiple emails in parallel."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {executor.submit(self.check_email, email): email for email in emails}
            
            for future in concurrent.futures.as_completed(future_to_email):
                email = future_to_email[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Email {email}: {result.result.value}")
                except Exception as e:
                    logger.error(f"Error checking email {email}: {str(e)}")
                    results.append(VerificationResult(
                        email=email,
                        result=EmailVerificationResult.ERROR,
                        message=f"Error: {str(e)}"
                    ))
        
        return results
    
    def get_proxy_stats(self) -> Dict:
        """Get statistics about the proxies."""
        return self.proxy_manager.get_stats()


# ---- Command Line Interface ----

def main():
    """Main entry point for the command line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check if Gmail addresses are registered")
    parser.add_argument("emails", nargs="*", help="Email addresses to check")
    parser.add_argument("-f", "--file", help="File containing email addresses (one per line)")
    parser.add_argument("-p", "--proxies", required=True, help="Proxy source (file path or URL)")
    parser.add_argument("-m", "--method", choices=["smtp", "http"], default="http", help="Verification method")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create verification strategy
    if args.method == "smtp":
        strategy = SmtpVerificationStrategy()
    else:
        strategy = HttpVerificationStrategy()
    
    # Create checker
    checker = GmailChecker(verification_strategy=strategy)
    
    # Load proxies
    logger.info(f"Loading proxies from {args.proxies}")
    checker.load_proxies(args.proxies)
    
    # Get emails to check
    emails = []
    
    if args.emails:
        emails.extend(args.emails)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_emails = [line.strip() for line in f if line.strip()]
                emails.extend(file_emails)
        except Exception as e:
            logger.error(f"Error reading email file: {str(e)}")
    
    if not emails:
        logger.error("No emails to check")
        return
    
    # Check emails
    logger.info(f"Checking {len(emails)} emails with {args.workers} workers")
    results = checker.check_emails_batch(emails, max_workers=args.workers)
    
    # Print results
    for result in results:
        status = result.result.value
        if result.result == EmailVerificationResult.VALID:
            status_str = f"VALID: {result.email}"
        elif result.result == EmailVerificationResult.INVALID:
            status_str = f"INVALID: {result.email}"
        else:
            status_str = f"{status.upper()}: {result.email} - {result.message}"
        
        print(status_str)
    
    # Save results to file if requested
    if args.output:
        try:
            output_data = [
                {
                    "email": r.email,
                    "result": r.result.value,
                    "message": r.message,
                    "proxy_used": r.proxy_used.address if r.proxy_used else None,
                    "response_time": r.response_time
                }
                for r in results
            ]
            
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            logger.info(f"Results saved to {args.output}")
        
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
    
    # Print proxy stats
    stats = checker.get_proxy_stats()
    logger.info(f"Proxy stats: {stats}")


if __name__ == "__main__":
    main()
