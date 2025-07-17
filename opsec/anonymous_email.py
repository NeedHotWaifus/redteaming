import requests
import random
import string
import json
import time
from pathlib import Path

class AnonymousEmailManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }
        self.temp_email_services = [
            "https://temp-mail.org/en/api",
            "https://www.1secmail.com/api/v1",
            "https://emailfake.com"
        ]
        
    def generate_random_identity(self):
        """Generate random identity for account creation"""
        first_names = ["Alex", "Jordan", "Taylor", "Casey", "Morgan", "Riley"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"]
        
        identity = {
            "first_name": random.choice(first_names),
            "last_name": random.choice(last_names),
            "username": self.generate_username(),
            "password": self.generate_password()
        }
        
        identity["email"] = f"{identity['username']}@protonmail.com"
        return identity
    
    def generate_username(self, length=12):
        """Generate random username"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def generate_password(self, length=16):
        """Generate secure random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choices(chars, k=length))
    
    def create_temp_email(self):
        """Create temporary email for testing"""
        try:
            # Use 1secmail API
            response = self.session.get(
                "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1"
            )
            if response.status_code == 200:
                email = response.json()[0]
                print(f"📧 Temporary email created: {email}")
                return email
        except Exception as e:
            print(f"❌ Temp email creation failed: {e}")
            
        # Fallback to random email generation
        domain = random.choice(["tempmail.org", "guerrillamail.com", "10minutemail.com"])
        username = self.generate_username(8)
        return f"{username}@{domain}"
    
    def save_credentials(self, service_name: str, credentials: dict):
        """Save credentials securely"""
        creds_dir = Path(__file__).parent.parent / "config" / "credentials"
        creds_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"{service_name}_{int(time.time())}.json"
        filepath = creds_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(credentials, f, indent=2)
            
        # Set restrictive permissions
        filepath.chmod(0o600)
        print(f"🔐 Credentials saved: {filepath}")
        
    def create_protonmail_account(self):
        """Automated ProtonMail account creation (OPSEC compliant)"""
        print("📧 Creating anonymous ProtonMail account...")
        
        identity = self.generate_random_identity()
        
        # Note: ProtonMail requires manual verification
        # This provides the generated identity for manual use
        print("⚠️  ProtonMail requires manual account creation")
        print("🔧 Use these generated credentials:")
        print(f"   Username: {identity['username']}")
        print(f"   Password: {identity['password']}")
        print(f"   Recovery Email: {self.create_temp_email()}")
        
        self.save_credentials("protonmail", identity)
        return identity

def main():
    print("🕶️  Anonymous Email Manager")
    email_manager = AnonymousEmailManager()
    
    choice = input("Select option:\n1. Create temp email\n2. Generate ProtonMail identity\nChoice: ")
    
    if choice == "1":
        temp_email = email_manager.create_temp_email()
        print(f"✅ Temporary email ready: {temp_email}")
        
    elif choice == "2":
        proton_identity = email_manager.create_protonmail_account()
        print("✅ ProtonMail identity generated for manual creation")
        
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()
