"""
Cryptographic key management for RedTeam Toolkit
"""

import os
import sys
import json
from pathlib import Path
import logging
import base64

# Ensure the config directory exists
CONFIG_DIR = Path(__file__).parent
SECURE_KEYS_DIR = CONFIG_DIR / "secure_keys"
SECURE_KEYS_DIR.mkdir(exist_ok=True, parents=True)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import cryptography modules with graceful fallback
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logger.warning("Cryptography module not found. Using fallback key generation.")
    CRYPTOGRAPHY_AVAILABLE = False

def generate_ssh_key_pair():
    """Generate SSH key pair for secure communication"""
    
    # Set paths for key files
    private_key_path = SECURE_KEYS_DIR / "ssh_private_key.key"
    public_key_path = SECURE_KEYS_DIR / "ssh_public_key.pub"
    
    try:
        if CRYPTOGRAPHY_AVAILABLE:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_key_ssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            
            # Write keys to files
            with open(private_key_path, 'wb') as f:
                f.write(private_key_pem)
                
            with open(public_key_path, 'wb') as f:
                f.write(public_key_ssh)
                
            logger.info(f"SSH key pair generated: {public_key_path}")
            
            return {
                "private_key": private_key_pem.decode('utf-8'),
                "public_key": public_key_ssh.decode('utf-8')
            }
        else:
            # Fallback key generation using os.system
            # This is less secure but works without cryptography
            logger.warning("Using fallback key generation method")
            
            # Check if ssh-keygen is available
            if os.system("ssh-keygen -h > /dev/null 2>&1") != 0:
                # If ssh-keygen is not available, create dummy keys
                dummy_private = "-----BEGIN RSA PRIVATE KEY-----\nMIIEFALLBACK\n-----END RSA PRIVATE KEY-----"
                dummy_public = "ssh-rsa FALLBACK"
                
                with open(private_key_path, 'w') as f:
                    f.write(dummy_private)
                    
                with open(public_key_path, 'w') as f:
                    f.write(dummy_public)
                    
                logger.warning("Created fallback dummy SSH keys")
                
                return {
                    "private_key": dummy_private,
                    "public_key": dummy_public
                }
            else:
                # Use ssh-keygen to create keys
                os.system(f"ssh-keygen -t rsa -b 2048 -f {private_key_path} -N \"\"")
                
                # Read generated keys
                with open(private_key_path, 'r') as f:
                    private_key = f.read()
                    
                with open(f"{private_key_path}.pub", 'r') as f:
                    public_key = f.read()
                    
                # Move public key to correct location
                os.rename(f"{private_key_path}.pub", public_key_path)
                
                logger.info(f"SSH key pair generated using ssh-keygen: {public_key_path}")
                
                return {
                    "private_key": private_key,
                    "public_key": public_key
                }
    except Exception as e:
        logger.error(f"Failed to generate SSH key pair: {e}")
        return None

def generate_aes_key():
    """Generate AES key for symmetric encryption"""
    try:
        if CRYPTOGRAPHY_AVAILABLE:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(os.urandom(32))
            
            return {
                "key": base64.b64encode(key).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8')
            }
        else:
            # Fallback using os.urandom
            key = os.urandom(32)
            salt = os.urandom(16)
            
            return {
                "key": base64.b64encode(key).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8')
            }
    except Exception as e:
        logger.error(f"Failed to generate AES key: {e}")
        return None

# Add missing key storage functions
def save_key(key_name, key_value):
    """Save a key to the secure storage"""
    key_path = SECURE_KEYS_DIR / f"{key_name}.key"
    try:
        with open(key_path, 'w') as f:
            f.write(str(key_value))
        logger.info(f"Key saved: {key_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to save key {key_name}: {e}")
        return False

def load_key(key_name, default=None):
    """Load a key from secure storage"""
    key_path = SECURE_KEYS_DIR / f"{key_name}.key"
    try:
        if key_path.exists():
            with open(key_path, 'r') as f:
                return f.read().strip()
        return default
    except Exception as e:
        logger.error(f"Failed to load key {key_name}: {e}")
        return default

def get_ssh_public_key():
    """Get the SSH public key, generating one if it doesn't exist"""
    public_key = load_key("ssh_public_key")
    if not public_key:
        key_pair = generate_ssh_key_pair()
        if key_pair:
            public_key = key_pair["public_key"]
    
    return public_key

# Define default SSH key
DEFAULT_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3s4FbJ/Tr4wV1EL9xcASmPicmeDLz1R6FhkmkspKMoGkK"

if __name__ == "__main__":
    # Test key generation
    ssh_keys = generate_ssh_key_pair()
    if ssh_keys:
        print("SSH keys generated successfully")
    
    aes_key = generate_aes_key()
    if aes_key:
        print("AES key generated successfully")

# Export functions and variables for use in config
__all__ = [
    'generate_ssh_key_pair', 
    'save_key', 
    'load_key', 
    'get_ssh_public_key',
    'get_api_token',
    'rotate_keys',
    'DEFAULT_SSH_KEY'
]
