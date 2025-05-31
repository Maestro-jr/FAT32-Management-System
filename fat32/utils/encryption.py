#!/usr/bin/env python3
"""
Advanced File Encryption System for FAT32 Virtual Disk Management
Provides secure encryption/decryption with multiple algorithms and key derivation
"""

import os
import hashlib
import hmac
import secrets
from typing import Union, Optional, Dict, Any, Tuple
from enum import Enum
import base64
import json
from dataclasses import dataclass, asdict
from pathlib import Path
import time

# Cryptographic imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    print("Warning: cryptography library not available. Using fallback encryption.")
    CRYPTOGRAPHY_AVAILABLE = False

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    RSA_OAEP = "rsa-oaep"

class KeyDerivationFunction(Enum):
    """Supported key derivation functions"""
    PBKDF2_SHA256 = "pbkdf2-sha256"
    SCRYPT = "scrypt"

@dataclass
class EncryptionMetadata:
    """Metadata for encrypted content"""
    algorithm: str
    kdf: str
    salt: bytes
    iv: bytes
    tag: Optional[bytes] = None
    iterations: Optional[int] = None
    scrypt_n: Optional[int] = None
    scrypt_r: Optional[int] = None
    scrypt_p: Optional[int] = None
    timestamp: Optional[float] = None
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert bytes to base64 for JSON serialization
        for key, value in data.items():
            if isinstance(value, bytes):
                data[key] = base64.b64encode(value).decode('ascii')
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptionMetadata':
        """Create from dictionary"""
        # Convert base64 strings back to bytes
        for key, value in data.items():
            if key in ['salt', 'iv', 'tag'] and isinstance(value, str):
                data[key] = base64.b64decode(value.encode('ascii'))
        return cls(**data)

class EncryptionError(Exception):
    """Base exception for encryption operations"""
    pass

class DecryptionError(Exception):
    """Exception for decryption failures"""
    pass

class FileEncryption:
    """
    Advanced file encryption system with multiple algorithms and secure key derivation
    """
    
    # Default parameters
    DEFAULT_ALGORITHM = EncryptionAlgorithm.AES_256_GCM
    DEFAULT_KDF = KeyDerivationFunction.PBKDF2_SHA256
    DEFAULT_ITERATIONS = 100000
    DEFAULT_SCRYPT_N = 16384
    DEFAULT_SCRYPT_R = 8
    DEFAULT_SCRYPT_P = 1
    
    def __init__(self, algorithm: EncryptionAlgorithm = None, kdf: KeyDerivationFunction = None):
        self.algorithm = algorithm or self.DEFAULT_ALGORITHM
        self.kdf = kdf or self.DEFAULT_KDF
        self.backend = default_backend() if CRYPTOGRAPHY_AVAILABLE else None
        
        if not CRYPTOGRAPHY_AVAILABLE and self.algorithm != EncryptionAlgorithm.AES_256_CBC:
            # Fallback to simple AES-CBC if cryptography library is not available
            self.algorithm = EncryptionAlgorithm.AES_256_CBC
    
    def _generate_salt(self, length: int = 32) -> bytes:
        """Generate cryptographically secure random salt"""
        return secrets.token_bytes(length)
    
    def _generate_iv(self, length: int = 16) -> bytes:
        """Generate cryptographically secure random IV"""
        return secrets.token_bytes(length)
    
    def _derive_key_pbkdf2(self, password: str, salt: bytes, iterations: int = None) -> bytes:
        """Derive key using PBKDF2-SHA256"""
        if not CRYPTOGRAPHY_AVAILABLE:
            return self._fallback_pbkdf2(password, salt, iterations or self.DEFAULT_ITERATIONS)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=iterations or self.DEFAULT_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _derive_key_scrypt(self, password: str, salt: bytes, n: int = None, r: int = None, p: int = None) -> bytes:
        """Derive key using Scrypt"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise EncryptionError("Scrypt requires cryptography library")
        
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=n or self.DEFAULT_SCRYPT_N,
            r=r or self.DEFAULT_SCRYPT_R,
            p=p or self.DEFAULT_SCRYPT_P,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _fallback_pbkdf2(self, password: str, salt: bytes, iterations: int) -> bytes:
        """Fallback PBKDF2 implementation using hashlib"""
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-GCM"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise EncryptionError("AES-GCM requires cryptography library")
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def _decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise DecryptionError("AES-GCM requires cryptography library")
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _encrypt_aes_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt using AES-256-CBC with PKCS7 padding"""
        if CRYPTOGRAPHY_AVAILABLE:
            from cryptography.hazmat.primitives import padding as crypto_padding
            padder = crypto_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            return encryptor.update(padded_data) + encryptor.finalize()
        else:
            # Fallback implementation (simplified, not recommended for production)
            return self._fallback_aes_cbc_encrypt(data, key, iv)
    
    def _decrypt_aes_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using AES-256-CBC with PKCS7 padding"""
        if CRYPTOGRAPHY_AVAILABLE:
            from cryptography.hazmat.primitives import padding as crypto_padding
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = crypto_padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        else:
            # Fallback implementation
            return self._fallback_aes_cbc_decrypt(ciphertext, key, iv)
    
    def _fallback_aes_cbc_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Fallback AES-CBC encryption (simplified - not for production use)"""
        # This is a very basic implementation for demonstration
        # In practice, you should always use a proper cryptographic library
        raise EncryptionError("Fallback AES implementation not available. Please install cryptography library.")
    
    def _fallback_aes_cbc_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Fallback AES-CBC decryption (simplified - not for production use)"""
        raise DecryptionError("Fallback AES implementation not available. Please install cryptography library.")
    
    def _encrypt_chacha20_poly1305(self, data: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise EncryptionError("ChaCha20-Poly1305 requires cryptography library")
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def _decrypt_chacha20_poly1305(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise DecryptionError("ChaCha20-Poly1305 requires cryptography library")
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt(self, data: Union[str, bytes], password: str, **kwargs) -> bytes:
        """
        Encrypt data with password
        
        Args:
            data: Data to encrypt (string or bytes)
            password: Password for encryption
            **kwargs: Additional parameters (iterations, scrypt params, etc.)
        
        Returns:
            Encrypted data with metadata
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate salt and IV/nonce
        salt = self._generate_salt()
        
        # Derive key based on KDF
        if self.kdf == KeyDerivationFunction.PBKDF2_SHA256:
            iterations = kwargs.get('iterations', self.DEFAULT_ITERATIONS)
            key = self._derive_key_pbkdf2(password, salt, iterations)
            kdf_params = {'iterations': iterations}
        elif self.kdf == KeyDerivationFunction.SCRYPT:
            n = kwargs.get('scrypt_n', self.DEFAULT_SCRYPT_N)
            r = kwargs.get('scrypt_r', self.DEFAULT_SCRYPT_R)
            p = kwargs.get('scrypt_p', self.DEFAULT_SCRYPT_P)
            key = self._derive_key_scrypt(password, salt, n, r, p)
            kdf_params = {'scrypt_n': n, 'scrypt_r': r, 'scrypt_p': p}
        else:
            raise EncryptionError(f"Unsupported KDF: {self.kdf}")
        
        # Encrypt based on algorithm
        if self.algorithm == EncryptionAlgorithm.AES_256_GCM:
            iv = self._generate_iv(12)  # GCM uses 96-bit nonce
            ciphertext, tag = self._encrypt_aes_gcm(data, key, iv)
            metadata = EncryptionMetadata(
                algorithm=self.algorithm.value,
                kdf=self.kdf.value,
                salt=salt,
                iv=iv,
                tag=tag,
                timestamp=time.time(),
                **kdf_params
            )
        elif self.algorithm == EncryptionAlgorithm.AES_256_CBC:
            iv = self._generate_iv(16)  # CBC uses 128-bit IV
            ciphertext = self._encrypt_aes_cbc(data, key, iv)
            tag = None
            metadata = EncryptionMetadata(
                algorithm=self.algorithm.value,
                kdf=self.kdf.value,
                salt=salt,
                iv=iv,
                tag=tag,
                timestamp=time.time(),
                **kdf_params
            )
        elif self.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            nonce = self._generate_iv(12)  # ChaCha20 uses 96-bit nonce
            ciphertext, tag = self._encrypt_chacha20_poly1305(data, key, nonce)
            metadata = EncryptionMetadata(
                algorithm=self.algorithm.value,
                kdf=self.kdf.value,
                salt=salt,
                iv=nonce,
                tag=tag,
                timestamp=time.time(),
                **kdf_params
            )
        else:
            raise EncryptionError(f"Unsupported algorithm: {self.algorithm}")
        
        # Combine metadata and ciphertext
        metadata_json = json.dumps(metadata.to_dict()).encode('utf-8')
        metadata_length = len(metadata_json).to_bytes(4, 'big')
        
        return metadata_length + metadata_json + ciphertext
    
    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data with password
        
        Args:
            encrypted_data: Encrypted data with metadata
            password: Password for decryption
        
        Returns:
            Decrypted data
        """
        try:
            # Extract metadata length
            metadata_length = int.from_bytes(encrypted_data[:4], 'big')
            
            # Extract metadata
            metadata_json = encrypted_data[4:4+metadata_length]
            metadata_dict = json.loads(metadata_json.decode('utf-8'))
            metadata = EncryptionMetadata.from_dict(metadata_dict)
            
            # Extract ciphertext
            ciphertext = encrypted_data[4+metadata_length:]
            
            # Derive key based on stored KDF parameters
            if metadata.kdf == KeyDerivationFunction.PBKDF2_SHA256.value:
                key = self._derive_key_pbkdf2(password, metadata.salt, metadata.iterations)
            elif metadata.kdf == KeyDerivationFunction.SCRYPT.value:
                key = self._derive_key_scrypt(
                    password, metadata.salt, 
                    metadata.scrypt_n, metadata.scrypt_r, metadata.scrypt_p
                )
            else:
                raise DecryptionError(f"Unsupported KDF: {metadata.kdf}")
            
            # Decrypt based on algorithm
            if metadata.algorithm == EncryptionAlgorithm.AES_256_GCM.value:
                return self._decrypt_aes_gcm(ciphertext, key, metadata.iv, metadata.tag)
            elif metadata.algorithm == EncryptionAlgorithm.AES_256_CBC.value:
                return self._decrypt_aes_cbc(ciphertext, key, metadata.iv)
            elif metadata.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305.value:
                return self._decrypt_chacha20_poly1305(ciphertext, key, metadata.iv, metadata.tag)
            else:
                raise DecryptionError(f"Unsupported algorithm: {metadata.algorithm}")
                
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")
    
    def encrypt_file(self, file_path: Union[str, Path], password: str, output_path: Optional[Union[str, Path]] = None, **kwargs) -> bool:
        """
        Encrypt a file
        
        Args:
            file_path: Path to file to encrypt
            password: Password for encryption
            output_path: Output path (defaults to file_path + '.enc')
            **kwargs: Additional encryption parameters
        
        Returns:
            Success status
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise EncryptionError(f"File not found: {file_path}")
            
            output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + '.enc')
            
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            encrypted_data = self.encrypt(data, password, **kwargs)
            
            # Write encrypted data
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return True
            
        except Exception as e:
            raise EncryptionError(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_path: Union[str, Path], password: str, output_path: Optional[Union[str, Path]] = None) -> bool:
        """
        Decrypt a file
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Password for decryption
            output_path: Output path (auto-detected if None)
        
        Returns:
            Success status
        """
        try:
            encrypted_file_path = Path(encrypted_file_path)
            if not encrypted_file_path.exists():
                raise DecryptionError(f"Encrypted file not found: {encrypted_file_path}")
            
            # Determine output path
            if output_path:
                output_path = Path(output_path)
            else:
                # Remove .enc extension if present
                if encrypted_file_path.suffix == '.enc':
                    output_path = encrypted_file_path.with_suffix('')
                else:
                    output_path = encrypted_file_path.with_suffix('.dec')
            
            # Read encrypted data
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decrypted_data = self.decrypt(encrypted_data, password)
            
            # Write decrypted data
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return True
            
        except Exception as e:
            raise DecryptionError(f"File decryption failed: {str(e)}")
    
    def verify_password(self, encrypted_data: bytes, password: str) -> bool:
        """
        Verify if password is correct without full decryption
        
        Args:
            encrypted_data: Encrypted data
            password: Password to verify
        
        Returns:
            True if password is correct
        """
        try:
            # Try to decrypt - if successful, password is correct
            self.decrypt(encrypted_data, password)
            return True
        except DecryptionError:
            return False
    
    def get_metadata(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Extract metadata from encrypted data
        
        Args:
            encrypted_data: Encrypted data with metadata
        
        Returns:
            Metadata dictionary
        """
        try:
            metadata_length = int.from_bytes(encrypted_data[:4], 'big')
            metadata_json = encrypted_data[4:4+metadata_length]
            return json.loads(metadata_json.decode('utf-8'))
        except Exception as e:
            raise EncryptionError(f"Failed to extract metadata: {str(e)}")
    
    def change_password(self, encrypted_data: bytes, old_password: str, new_password: str, **kwargs) -> bytes:
        """
        Change password for encrypted data
        
        Args:
            encrypted_data: Current encrypted data
            old_password: Current password
            new_password: New password
            **kwargs: New encryption parameters
        
        Returns:
            Re-encrypted data with new password
        """
        # Decrypt with old password
        decrypted_data = self.decrypt(encrypted_data, old_password)
        
        # Re-encrypt with new password
        return self.encrypt(decrypted_data, new_password, **kwargs)
    
    def generate_key_file(self, output_path: Union[str, Path], key_length: int = 32) -> bytes:
        """
        Generate a random key file for additional security
        
        Args:
            output_path: Path to save key file
            key_length: Length of key in bytes
        
        Returns:
            Generated key
        """
        key = secrets.token_bytes(key_length)
        
        with open(output_path, 'wb') as f:
            f.write(key)
        
        # Set restrictive permissions (Unix-like systems)
        try:
            os.chmod(output_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows or permission error
        
        return key
    
    def encrypt_with_key_file(self, data: Union[str, bytes], password: str, key_file_path: Union[str, Path], **kwargs) -> bytes:
        """
        Encrypt data using both password and key file
        
        Args:
            data: Data to encrypt
            password: Password
            key_file_path: Path to key file
            **kwargs: Additional parameters
        
        Returns:
            Encrypted data
        """
        # Read key file
        with open(key_file_path, 'rb') as f:
            key_file_data = f.read()
        
        # Combine password and key file data
        combined_password = password + base64.b64encode(key_file_data).decode('ascii')
        
        return self.encrypt(data, combined_password, **kwargs)
    
    def decrypt_with_key_file(self, encrypted_data: bytes, password: str, key_file_path: Union[str, Path]) -> bytes:
        """
        Decrypt data using both password and key file
        
        Args:
            encrypted_data: Encrypted data
            password: Password
            key_file_path: Path to key file
        
        Returns:
            Decrypted data
        """
        # Read key file
        with open(key_file_path, 'rb') as f:
            key_file_data = f.read()
        
        # Combine password and key file data
        combined_password = password + base64.b64encode(key_file_data).decode('ascii')
        
        return self.decrypt(encrypted_data, combined_password)


class RSAEncryption:
    """RSA encryption for key exchange and small data"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.backend = default_backend() if CRYPTOGRAPHY_AVAILABLE else None
        
        if not CRYPTOGRAPHY_AVAILABLE:
            raise EncryptionError("RSA encryption requires cryptography library")
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt(self, data: bytes, public_key_pem: bytes) -> bytes:
        """Encrypt data with public key"""
        public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
        
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """Decrypt data with private key"""
        private_key = serialization.load_pem_private_key(
            private_key_pem, 
            password=None, 
            backend=self.backend
        )
        
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class SecureRandom:
    """Cryptographically secure random number generation"""
    
    @staticmethod
    def bytes(length: int) -> bytes:
        """Generate random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def string(length: int, alphabet: str = None) -> str:
        """Generate random string"""
        if alphabet is None:
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def password(length: int = 16, include_symbols: bool = True) -> str:
        """Generate secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        if include_symbols:
            alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        return SecureRandom.string(length, alphabet)


# Utility functions
def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Hash password with salt using PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(32)
    
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed, salt

def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    """Verify password against hash"""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(hashed, computed_hash)

def secure_delete(file_path: Union[str, Path], passes: int = 3) -> bool:
    """
    Securely delete file by overwriting with random data
    
    Args:
        file_path: Path to file to delete
        passes: Number of overwrite passes
    
    Returns:
        Success status
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            return True
        
        file_size = file_path.stat().st_size
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        file_path.unlink()  # Delete file
        return True
        
    except Exception:
        return False


# Example usage and testing
if __name__ == "__main__":
    # Test basic encryption/decryption
    encryptor = FileEncryption()
    
    # Test string encryption
    original_text = "This is a secret message for testing encryption!"
    password = "my_secure_password_123"
    
    print("Testing string encryption...")
    encrypted = encryptor.encrypt(original_text, password)
    print(f"Encrypted size: {len(encrypted)} bytes")
    
    decrypted = encryptor.decrypt(encrypted, password)
    decrypted_text = decrypted.decode('utf-8')
    print(f"Decrypted: {decrypted_text}")
    print(f"Match: {original_text == decrypted_text}")
    
    # Test metadata extraction
    metadata = encryptor.get_metadata(encrypted)
    print(f"Metadata: {metadata}")
    
    # Test password verification
    print(f"Password correct: {encryptor.verify_password(encrypted, password)}")
    print(f"Wrong password: {encryptor.verify_password(encrypted, 'wrong_password')}")
    
    # Test different algorithms
    print("\nTesting different algorithms...")
    algorithms = [
        EncryptionAlgorithm.AES_256_GCM,
        EncryptionAlgorithm.AES_256_CBC,
    ]
    
    if CRYPTOGRAPHY_AVAILABLE:
        algorithms.append(EncryptionAlgorithm.CHACHA20_POLY1305)
    
    for algo in algorithms:
        print(f"Testing {algo.value}...")
        enc = FileEncryption(algorithm=algo)
        encrypted = enc.encrypt(original_text, password)
        decrypted = enc.decrypt(encrypted, password).decode('utf-8')
        print(f"  Result: {'PASS' if original_text == decrypted else 'FAIL'}")
    
    # Test secure random
    print(f"\nRandom password: {SecureRandom.password(16)}")
    print(f"Random string: {SecureRandom.string(10)}")
    
    print("\nEncryption module test completed!")
        