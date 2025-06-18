import base64
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class OllamaAuth:
    def __init__(self, key_path: str = None):
        """Initialize the OllamaAuth class.
        
        Args:
            key_path: Optional path to the private key file. If not provided,
                     defaults to ~/.ollama/id_ed25519
        """
        # Get the private key path
        if key_path is None:
            home = str(Path.home())
            self.key_path = os.path.join(home, '.ollama', 'id_ed25519')
        else:
            # Expand ~ and environment variables in the path
            self.key_path = os.path.expanduser(os.path.expandvars(key_path))
    
    def load_private_key(self):
        """Read and load the private key.
        
        Returns:
            The loaded Ed25519 private key.
            
        Raises:
            FileNotFoundError: If the key file doesn't exist
            ValueError: If the key file is invalid
        """
        try:
            # Read and load the private key
            with open(self.key_path, 'rb') as f:
                private_key_data = f.read()
                
            # Load the private key
            private_key = serialization.load_ssh_private_key(
                private_key_data,
                password=None  # Ollama uses unencrypted keys
            )
            return private_key
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Could not find Ollama private key at {self.key_path}. "
                "Please generate one using: ssh-keygen -t ed25519 -f ~/.ollama/id_ed25519 -N ''"
            )
        except Exception as e:
            raise ValueError(
                f"Invalid private key at {self.key_path}: {str(e)}"
            )
    
    def get_public_key_b64(self, private_key):
        """Get the base64 encoded public key.
        
        Args:
            private_key: The Ed25519 private key
            
        Returns:
            Base64 encoded public key string
        """
        # Get the public key in SSH format
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Convert to base64
        return base64.b64encode(public_key_bytes).decode('utf-8')
    
    def sign_request(self, method: str, path: str):
        """Sign an HTTP request.
        
        Args:
            method: The HTTP method (e.g. 'GET', 'POST')
            path: The request path (e.g. '/api/chat')
            
        Returns:
            A tuple of (auth_token, timestamp) where auth_token is the 
            authorization header value and timestamp is the request timestamp.
            
        Raises:
            FileNotFoundError: If the key file doesn't exist
            ValueError: If the key file is invalid
        """
        # Create the challenge string
        timestamp = str(int(time.time()))
        challenge = f"{method},{path}?ts={timestamp}"
        
        # Load the private key and sign
        private_key = self.load_private_key()
        signature = private_key.sign(challenge.encode())
        
        # Get the public key
        public_key_b64 = self.get_public_key_b64(private_key)
        
        # Create the authorization token
        auth_token = f"{public_key_b64}:{base64.b64encode(signature).decode('utf-8')}"
        
        return auth_token, timestamp 