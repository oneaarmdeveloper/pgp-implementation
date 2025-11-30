"""
Core PGP implementation
"""
import base64
from .crypto_utils import CryptoUtils
from .key_management import KeyManager
from .message_format import MessageFormatter


class PGP:
    """Main PGP Implementation class"""

    def __init__(self, keys_directory="keys"):
        """Initialize PGP instance"""
        self.key_manager = KeyManager(keys_directory)
        print("PGP initialized successfully!")

    def generate_keypair(self, user_id, key_size=2048, password=None):
        """Generate a new key pair for a user"""
        return self.key_manager.generate_keypair(user_id, key_size, password)

    def encrypt_message(self, message, recipient_id, sender_id=None):
        """Encrypt a message for a recipient"""
        print(f"Encrypting message for {recipient_id}...")

        # Convert message to bytes if needed
        message_bytes = message.encode("utf-8") if isinstance(message, str) else message

        # Load recipient public key
        try:
            recipient_public_key = self.key_manager.load_public_key(recipient_id)
        except FileNotFoundError:
            raise ValueError(f"Public key not found for recipient: {recipient_id}")

        # Hybrid encrypt using your existing secure method
        payload = CryptoUtils.hybrid_encrypt(message_bytes, recipient_public_key)

        # Extract components (base64 strings)
        encrypted_aes_key_b64 = payload["enc_session_key"]
        nonce_b64 = payload["nonce"]
        ciphertext_b64 = payload["ciphertext"]

        # Decode to bytes for MessageFormatter (which expects raw bytes)
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        encrypted_data = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(nonce_b64)  # In GCM, nonce = IV

        # Format PGP message
        pgp_message = MessageFormatter.format_encrypted_message(
            encrypted_aes_key, encrypted_data, iv, recipient_id, sender_id
        )

        print("Message encrypted successfully!")
        return pgp_message

    def decrypt_message(self, pgp_message, recipient_id, password=None):
        """Decrypt a PGP message"""
        print(f"Decrypting message for {recipient_id}...")

        # Parse message
        try:
            message_data = MessageFormatter.parse_pgp_message(pgp_message)
        except ValueError as e:
            raise ValueError(f"Failed to parse PGP message: {e}")

        # Check message type
        if message_data["type"] not in [
            MessageFormatter.ENCRYPTED_MESSAGE,
            MessageFormatter.ENCRYPTED_SIGNED_MESSAGE,
        ]:
            raise ValueError("Message is not encrypted")

        # Verify recipient
        if message_data["recipient"] != recipient_id:
            raise ValueError(f"Message is not for {recipient_id}")

        # Load recipient private key
        try:
            recipient_private_key = self.key_manager.load_private_key(
                recipient_id, password
            )
        except FileNotFoundError:
            raise ValueError(f"Private key not found for {recipient_id}")

        # Prepare payload for hybrid_decrypt (base64 strings)
        payload = {
            "enc_session_key": base64.b64encode(message_data["encrypted_key"]).decode(),
            "nonce": base64.b64encode(message_data["iv"]).decode(),
            "ciphertext": base64.b64encode(message_data["encrypted_data"]).decode()
        }

        # Hybrid decrypt
        try:
            decrypted_data = CryptoUtils.hybrid_decrypt(payload, recipient_private_key)
        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {e}")

        # Verify signature if signed
        if message_data["type"] == MessageFormatter.ENCRYPTED_SIGNED_MESSAGE:
            print("Verifying signature...")
            sender_id = message_data["sender"]

            try:
                sender_public_key = self.key_manager.load_public_key(sender_id)
                is_valid = CryptoUtils.verify_signature(
                    decrypted_data, message_data["signature"], sender_public_key
                )

                if is_valid:
                    print("Signature verification successful!")
                else:
                    print("Signature verification failed")

            except FileNotFoundError:
                print(f"Cannot verify signature: public key not found for {sender_id}")

        print("Message decrypted successfully")
        return decrypted_data.decode("utf-8")

    def sign_message(self, message, signer_id, password=None):
        """Create a digital signature for a message"""
        print(f"Signing message as {signer_id}...")

        message_bytes = message.encode("utf-8") if isinstance(message, str) else message

        # Load signer private key
        try:
            signer_private_key = self.key_manager.load_private_key(
                signer_id, password
            )
        except FileNotFoundError:
            raise ValueError(f"Private key not found for {signer_id}")

        # Create signature
        signature = CryptoUtils.sign_data(message_bytes, signer_private_key)

        # Format signed message
        pgp_message = MessageFormatter.format_signed_message(
            message_bytes, signature, signer_id
        )

        print("Message signed successfully")
        return pgp_message

    def verify_signature(self, pgp_signed_message):
        """Verify a digitally signed message"""
        print("Verifying message signature...")

        # Parse message
        try:
            message_data = MessageFormatter.parse_pgp_message(pgp_signed_message)
        except ValueError as e:
            raise ValueError(f"Failed to parse PGP message: {e}")

        # Verify correct type
        if message_data["type"] != MessageFormatter.SIGNED_MESSAGE:
            raise ValueError("This is not a signed message")

        signer_id = message_data["signer"]

        # Load public key
        try:
            signer_public_key = self.key_manager.load_public_key(signer_id)
        except FileNotFoundError:
            raise ValueError(f"Public key not found for signer: {signer_id}")

        is_valid = CryptoUtils.verify_signature(
            message_data["message"],
            message_data["signature"],
            signer_public_key,
        )

        result = {
            "is_valid": is_valid,
            "signer": signer_id,
            "message": message_data["message"].decode("utf-8"),
            "timestamp": message_data["timestamp"],
        }

        print("Signature verification successful!" if is_valid else "Signature verification failed")
        return result

    def encrypt_and_sign_message(self, message, recipient_id, sender_id, sender_password=None):
        """Encrypt AND sign message"""
        print(f"Encrypting and signing message from {sender_id} to {recipient_id}...")

        message_bytes = message.encode("utf-8") if isinstance(message, str) else message

        # Load keys
        try:
            recipient_public_key = self.key_manager.load_public_key(recipient_id)
        except FileNotFoundError:
            raise ValueError(f"Public key not found for recipient: {recipient_id}")

        try:
            sender_private_key = self.key_manager.load_private_key(
                sender_id, sender_password
            )
        except FileNotFoundError:
            raise ValueError(f"Private key not found for sender: {sender_id}")

        # Create signature
        signature = CryptoUtils.sign_data(message_bytes, sender_private_key)

        # Hybrid encrypt
        payload = CryptoUtils.hybrid_encrypt(message_bytes, recipient_public_key)

        # Extract components
        encrypted_aes_key = base64.b64decode(payload["enc_session_key"])
        encrypted_data = base64.b64decode(payload["ciphertext"])
        iv = base64.b64decode(payload["nonce"])

        # Format final PGP message
        pgp_message = MessageFormatter.format_encrypted_signed_message(
            encrypted_aes_key, encrypted_data, iv, signature, recipient_id, sender_id
        )

        print("Message encrypted and signed successfully!")
        return pgp_message

    def list_keys(self):
        """List all available keys"""
        return self.key_manager.list_keys()

    def export_public_key(self, user_id, output_file=None):
        """Export a user's public key"""
        return self.key_manager.export_public_key(user_id, output_file)

    def import_public_key(self, user_id, key_file):
        """Import a public key"""
        return self.key_manager.import_public_key(user_id, key_file)

    def delete_keypair(self, user_id):
        """Delete keypair for a user"""
        self.key_manager.delete_keypair(user_id)


if __name__ == "__main__":
    # Demo: generate key, encrypt, decrypt
    pgp = PGP()
    pgp.generate_keypair("Anselm")
    pgp.generate_keypair("Esther")

    msg = "Secret message from Anselm to Esther"
    encrypted = pgp.encrypt_message(msg, recipient_id="Esther", sender_id="Anselm")
    print("\nEncrypted message:\n", encrypted)

    decrypted = pgp.decrypt_message(encrypted, recipient_id="Esther")
    print("\nDecrypted message:", decrypted)