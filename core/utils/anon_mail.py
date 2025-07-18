"""
Anonymous Email Generator Module
Provides functionality for temporary and anonymous email generation
"""

import os
import sys
import random
import string
import json
import time
from pathlib import Path
import logging
from typing import Dict, List, Optional, Tuple

# Try to import requests with fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests module not found. Limited functionality available.")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnonMailGenerator:
    """Class for generating and managing anonymous/temporary email addresses"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize the anonymous email generator
        
        Args:
            config_dir: Directory to store configuration and credentials
        """
        if config_dir is None:
            # Default to the config directory in the toolkit
            self.config_dir = Path(__file__).parent.parent.parent.parent / "configs"
        else:
            self.config_dir = config_dir
            
        self.config_dir.mkdir(exist_ok=True, parents=True)
        self.config_file = self.config_dir / "anon_mail_config.json"
        self.load_config()
        
    def load_config(self) -> None:
        """Load configuration from file or create default"""
        default_config = {
            "services": {
                "temp_mail": {
                    "enabled": True,
                    "domains": ["temp-mail.org", "tmpmail.net", "temp-mail.io"],
                    "api_url": "https://api.temp-mail.org/request/",
                    "api_key": ""
                },
                "protonmail": {
                    "enabled": True,
                    "domains": ["protonmail.com", "proton.me"],
                    "api_url": "",
                    "api_key": ""
                },
                "guerrilla_mail": {
                    "enabled": True,
                    "domains": ["guerrillamail.com", "guerrillamail.net", "guerrillamail.org"],
                    "api_url": "https://api.guerrillamail.com/ajax.php",
                    "api_key": ""
                }
            },
            "default_service": "temp_mail",
            "generated_emails": [],
            "last_used": None
        }
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = default_config
                self.save_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = default_config
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def generate_random_email(self, service: Optional[str] = None) -> str:
        """
        Generate a random email address
        
        Args:
            service: The email service to use (defaults to configured default)
            
        Returns:
            A randomly generated email address
        """
        if service is None:
            service = self.config.get("default_service", "temp_mail")
            
        if service not in self.config["services"] or not self.config["services"][service]["enabled"]:
            logger.warning(f"Service {service} not available, using fallback")
            service = "temp_mail"  # Fallback to temp-mail
        
        # Generate random username
        username_length = random.randint(8, 12)
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=username_length))
        
        # Get random domain from the service
        domains = self.config["services"][service]["domains"]
        domain = random.choice(domains)
        
        # Construct email
        email = f"{username}@{domain}"
        
        # Save to generated emails
        self.config["generated_emails"].append({
            "email": email,
            "service": service,
            "created": time.time(),
            "last_checked": None
        })
        self.config["last_used"] = email
        self.save_config()
        
        return email
    
    def check_emails(self, email: Optional[str] = None) -> List[Dict]:
        """
        Check emails for a generated address
        
        Args:
            email: The email address to check (defaults to last used)
            
        Returns:
            List of received emails
        """
        if not REQUESTS_AVAILABLE:
            logger.error("Cannot check emails: requests module not available")
            return []
            
        if email is None:
            email = self.config.get("last_used")
            if email is None:
                logger.error("No email address specified or last used")
                return []
        
        # Find the service for this email
        service = None
        for generated in self.config["generated_emails"]:
            if generated["email"] == email:
                service = generated["service"]
                break
                
        if service is None:
            logger.error(f"Unknown email address: {email}")
            return []
            
        service_config = self.config["services"][service]
        
        # Check emails based on service
        if service == "temp_mail":
            return self._check_temp_mail(email, service_config)
        elif service == "guerrilla_mail":
            return self._check_guerrilla_mail(email, service_config)
        else:
            logger.error(f"Service {service} does not support checking emails")
            return []
    
    def _check_temp_mail(self, email: str, service_config: Dict) -> List[Dict]:
        """
        Check emails for temp-mail service
        
        Args:
            email: The email address to check
            service_config: Service configuration
            
        Returns:
            List of received emails
        """
        try:
            api_url = service_config["api_url"]
            response = requests.get(f"{api_url}mail/id/{email}")
            if response.status_code == 200:
                data = response.json()
                # Update last checked time
                for generated in self.config["generated_emails"]:
                    if generated["email"] == email:
                        generated["last_checked"] = time.time()
                        break
                self.save_config()
                return data.get("mail", [])
            else:
                logger.error(f"API error: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error checking temp-mail: {e}")
            return []
    
    def _check_guerrilla_mail(self, email: str, service_config: Dict) -> List[Dict]:
        """
        Check emails for guerrilla mail service
        
        Args:
            email: The email address to check
            service_config: Service configuration
            
        Returns:
            List of received emails
        """
        try:
            api_url = service_config["api_url"]
            response = requests.get(f"{api_url}?f=check_email&email_addr={email}")
            if response.status_code == 200:
                data = response.json()
                # Update last checked time
                for generated in self.config["generated_emails"]:
                    if generated["email"] == email:
                        generated["last_checked"] = time.time()
                        break
                self.save_config()
                return data.get("list", [])
            else:
                logger.error(f"API error: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error checking guerrilla mail: {e}")
            return []
    
    def get_generated_emails(self) -> List[Dict]:
        """
        Get list of all generated email addresses
        
        Returns:
            List of generated email addresses with metadata
        """
        return self.config["generated_emails"]
    
    def get_last_used_email(self) -> Optional[str]:
        """
        Get the last used email address
        
        Returns:
            Last used email address or None if none used
        """
        return self.config.get("last_used")
    
    def configure_service(self, service: str, api_key: str) -> bool:
        """
        Configure a service with an API key
        
        Args:
            service: Service name
            api_key: API key for the service
            
        Returns:
            True if configuration successful, False otherwise
        """
        if service not in self.config["services"]:
            logger.error(f"Unknown service: {service}")
            return False
            
        self.config["services"][service]["api_key"] = api_key
        return self.save_config()

def generate_anon_email() -> str:
    """
    Convenience function to generate an anonymous email
    
    Returns:
        A randomly generated email address
    """
    generator = AnonMailGenerator()
    return generator.generate_random_email()

def check_anon_email(email: Optional[str] = None) -> List[Dict]:
    """
    Convenience function to check emails for an anonymous address
    
    Args:
        email: The email address to check (defaults to last used)
        
    Returns:
        List of received emails
    """
    generator = AnonMailGenerator()
    return generator.check_emails(email)

if __name__ == "__main__":
    # Test the functionality
    generator = AnonMailGenerator()
    email = generator.generate_random_email()
    print(f"Generated email: {email}")
    
    emails = generator.check_emails(email)
    print(f"Found {len(emails)} emails")
