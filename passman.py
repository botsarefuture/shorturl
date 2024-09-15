import hashlib
import os

class PasswordManager:
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password with a random salt and return salt + hash."""
        # Generate a random 16-byte salt
        salt = os.urandom(16)
        # Hash the password using PBKDF2-HMAC with SHA-256
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        # Return the salt and hash concatenated
        return salt + hashed

    @staticmethod
    def check_password(stored_password: bytes, provided_password: str) -> bool:
        """Check if a provided password matches the stored hashed password."""
        # Convert provided_password to bytes
        provided_password_bytes = provided_password.encode()

        print(provided_password_bytes, type(provided_password_bytes))
        
        # Extract the salt (first 16 bytes) from stored_password
        salt = stored_password[:16]
        # Extract the hash (remaining bytes) from stored_password
        stored_hash = stored_password[16:]
        
        # Hash the provided password with the extracted salt
        hashed = hashlib.pbkdf2_hmac('sha256', provided_password_bytes, salt, 100000)
        
        # Return True if the hashes match
        return hashed == stored_hash
