# crypto_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64

class MessageEncryption:
    """AES-256 encryption for messages"""
    
    @staticmethod
    def encrypt(message, key):
        """Encrypt message using AES-256-CBC"""
        iv = os.urandom(16)
        padded_message = MessageEncryption._pad(message.encode('utf-8'))
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    @staticmethod
    def decrypt(ciphertext_b64, iv_b64, key):
        """Decrypt message using AES-256-CBC"""
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        message = MessageEncryption._unpad(padded_message)
        
        return message.decode('utf-8')
    
    @staticmethod
    def _pad(data):
        """PKCS7 padding"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    @staticmethod
    def _unpad(data):
        """Remove PKCS7 padding"""
        pad_len = data[-1]
        return data[:-pad_len]


class HashingUtils:
    """Hashing utilities for messages"""
    
    @staticmethod
    def hash_message(message, salt=None):
        """Hash message with salt for integrity"""
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)
        
        hash_obj = hashlib.sha256()
        hash_obj.update(salt)
        hash_obj.update(message.encode('utf-8'))
        
        return {
            'hash': hash_obj.hexdigest(),
            'salt': salt.hex()
        }
    
    @staticmethod
    def verify_message_hash(message, expected_hash, salt_hex):
        """Verify message integrity"""
        computed = HashingUtils.hash_message(message, salt_hex)
        return computed['hash'] == expected_hash


class DigitalSignature:
    """RSA digital signatures"""
    
    @staticmethod
    def sign_message(message, private_key_pem):
        """Sign message with private key"""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        message_bytes = message.encode('utf-8')
        signature = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(message, signature_b64, public_key_pem):
        """Verify message signature"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            signature = base64.b64decode(signature_b64)
            message_bytes = message.encode('utf-8')
            
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False


class KeyDerivation:
    """Derive AES keys"""
    
    @staticmethod
    def derive_key(sender_id, receiver_id):
        """Derive AES key from sender and receiver IDs"""
        key_material = f"stego-{sender_id}-{receiver_id}-secret".encode('utf-8')
        key = hashlib.sha256(key_material).digest()
        return key