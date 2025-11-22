"""
cryptoutils.py

Secure, corrected cryptographic utilities for hybrid (PGP-like) use:
- RSA keypair generation (2048 or 4096 bits recommended)
- Serialize / load private/public keys (PEM, optional password)
- AES-256 key generation
- Authenticated symmetric encryption (AES-GCM)
- RSA OAEP encrypt/decrypt (for session key)
- Sign / verify with RSA-PSS + SHA-256
- SHA-256 hashing helper
- PKCS7 pad/unpad (provided for compatibility, but prefer AES-GCM)
- Hybrid helpers: encrypt (produce encrypted session key + ciphertext), decrypt
- Base64 helpers for easy serialization/transmission
"""
import sys
print("PYTHON EXECUTABLE:", sys.executable)
print("PYTHON PATH:", sys.path)


import os
import base64
import hashlib
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


class CryptoUtils:
    """Cryptographic utilities (safe defaults)."""

    # ------------------------
    # Key generation / serialization
    # ------------------------
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA private/public key pair.
        Default key_size=2048 (use 4096 if you need stronger security, at cost of performance).
        """
        if key_size not in (2048, 3072, 4096):
            raise ValueError("Use a standard RSA key size: 2048, 3072, or 4096 bits.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
        """
        Serialize private key to PEM.
        If password is provided, the PEM will be encrypted with best available encryption.
        """
        if password:
            enc_alg = serialization.BestAvailableEncryption(password.encode())
        else:
            enc_alg = serialization.NoEncryption()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg
        )
        return pem

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serialize public key to PEM (SubjectPublicKeyInfo).
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    @staticmethod
    def load_private_key(pem_data: bytes, password: Optional[str] = None) -> rsa.RSAPrivateKey:
        """
        Load a private key from PEM bytes. Provide password if the PEM is encrypted.
        """
        pw = password.encode() if password else None
        private_key = serialization.load_pem_private_key(pem_data, password=pw)
        return private_key

    @staticmethod
    def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """
        Load a public key from PEM bytes.
        """
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key

    # ------------------------
    # Symmetric key (AES)
    # ------------------------
    @staticmethod
    def generate_aes_key() -> bytes:
        """
        Generate a random 32-byte AES-256 key.
        """
        return os.urandom(32)

    # AES-GCM helpers (authenticated encryption)
    @staticmethod
    def aes_gcm_encrypt(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Dict[str, str]:
        """
        Encrypt plaintext using AES-256-GCM.
        Returns a dict containing base64-encoded: nonce, ciphertext (includes tag).
        AESGCM.encrypt returns ciphertext||tag; we return that as 'ciphertext'.
        """
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes for AES-256.")

        # Recommended nonce length for GCM is 12 bytes
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data)

        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()
        }

    @staticmethod
    def aes_gcm_decrypt(nonce_b64: str, ciphertext_b64: str, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt AES-GCM ciphertext (base64 inputs for nonce and ciphertext).
        Returns plaintext bytes.
        Raises cryptography.exceptions.InvalidTag on authentication failure.
        """
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ciphertext_b64)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct, associated_data)
        return plaintext

    # ------------------------
    # RSA encrypt/decrypt (OAEP)
    # ------------------------
    @staticmethod
    def rsa_encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypt data using RSA OAEP (with SHA-256).
        Suitable for encrypting small blobs (session keys).
        """
        ciphertext = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decrypt RSA OAEP ciphertext using private key.
        """
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    # ------------------------
    # Signing / verification
    # ------------------------
    @staticmethod
    def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Create an RSA-PSS signature (SHA-256) for the provided data.
        """
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify an RSA-PSS signature. Returns True if valid, False otherwise.
        """
        try:
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    # ------------------------
    # Hashing
    # ------------------------
    @staticmethod
    def hash_data_sha256(data: bytes) -> bytes:
        """
        Return SHA-256 digest of data.
        """
        h = hashlib.sha256()
        h.update(data)
        return h.digest()

    # ------------------------
    # PKCS7 padding (legacy; not required for AES-GCM)
    # ------------------------
    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        """
        Add PKCS#7 padding. block_size in bytes (default 16).
        """
        if block_size < 1 or block_size > 255:
            raise ValueError("block_size must be between 1 and 255")
        pad_len = block_size - (len(data) % block_size)
        pad = bytes([pad_len]) * pad_len
        return data + pad

    @staticmethod
    def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
        """
        Remove PKCS#7 padding. Raises ValueError on bad padding.
        """
        if not padded or len(padded) % block_size != 0:
            raise ValueError("Invalid padded data length")
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Invalid padding length")
        if padded[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid padding bytes")
        return padded[:-pad_len]

    # ------------------------
    # Hybrid (PGP-like) helpers
    # ------------------------
    @staticmethod
    def hybrid_encrypt(plaintext: bytes, receiver_public_key: rsa.RSAPublicKey, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Hybrid encrypt:
        - generate AES-256 session key
        - encrypt plaintext with AES-GCM
        - encrypt AES key with receiver's RSA public key (OAEP-SHA256)
        Returns a dict ready for JSON encoding (all binary parts are base64 strings).
        """
        session_key = CryptoUtils.generate_aes_key()
        aes_encrypted = CryptoUtils.aes_gcm_encrypt(plaintext, session_key, associated_data)

        enc_session_key = CryptoUtils.rsa_encrypt(session_key, receiver_public_key)

        return {
            "enc_session_key": base64.b64encode(enc_session_key).decode(),
            "nonce": aes_encrypted["nonce"],
            "ciphertext": aes_encrypted["ciphertext"]
        }

    @staticmethod
    def hybrid_decrypt(payload: Dict[str, Any], receiver_private_key: rsa.RSAPrivateKey, associated_data: Optional[bytes] = None) -> bytes:
        """
        Hybrid decrypt payload produced by hybrid_encrypt.
        Expects payload keys: enc_session_key (base64), nonce (base64), ciphertext (base64).
        """
        enc_session_key = base64.b64decode(payload["enc_session_key"])
        session_key = CryptoUtils.rsa_decrypt(enc_session_key, receiver_private_key)
        plaintext = CryptoUtils.aes_gcm_decrypt(payload["nonce"], payload["ciphertext"], session_key, associated_data)
        return plaintext

    # ------------------------
    # Helpers for base64 I/O (optional)
    # ------------------------
    @staticmethod
    def b64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode()

    @staticmethod
    def b64_decode(data_b64: str) -> bytes:
        return base64.b64decode(data_b64)


# ------------------------
# Example usage / self-test
# ------------------------
if __name__ == "__main__":
    # quick self-test demonstrating generation, hybrid encryption, signing
    message = b"Hello, this is a secret message."
    print("Generating RSA key pair...")
    priv, pub = CryptoUtils.generate_rsa_keypair(2048)

    # serialize & reload roundtrip
    pem_priv = CryptoUtils.serialize_private_key(priv, password=None)
    pem_pub = CryptoUtils.serialize_public_key(pub)
    loaded_priv = CryptoUtils.load_private_key(pem_priv, password=None)
    loaded_pub = CryptoUtils.load_public_key(pem_pub)

    # hybrid encrypt
    print("Hybrid encrypting message...")
    payload = CryptoUtils.hybrid_encrypt(message, loaded_pub)
    print("Payload:", payload)

    # hybrid decrypt
    print("Hybrid decrypting message...")
    recovered = CryptoUtils.hybrid_decrypt(payload, loaded_priv)
    print("Recovered:", recovered)

    # sign / verify
    print("Signing message...")
    sig = CryptoUtils.sign_data(message, loaded_priv)
    ok = CryptoUtils.verify_signature(message, sig, loaded_pub)
    print("Signature valid:", ok)

    # hash
    print("SHA-256:", CryptoUtils.b64_encode(CryptoUtils.hash_data_sha256(message)))

    # pkcs7 (demonstration)
    padded = CryptoUtils.pkcs7_pad(b"ABC", 16)
    unp = CryptoUtils.pkcs7_unpad(padded, 16)
    assert unp == b"ABC"
    print("PKCS7 pad/unpad OK")

