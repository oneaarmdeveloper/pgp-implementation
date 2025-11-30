"""
PGP message formatting and parsing
"""
import base64
import json
from datetime import datetime


class MessageFormatter:
    """Handles PGP message formatting and parsing"""

    # Message type constants
    ENCRYPTED_MESSAGE = "PGP_ENCRYPTED_MESSAGE"
    SIGNED_MESSAGE = "PGP_SIGNED_MESSAGE"
    ENCRYPTED_SIGNED_MESSAGE = "PGP_ENCRYPTED_SIGNED_MESSAGE"

    @staticmethod
    def format_encrypted_message(encrypted_aes_key, encrypted_data, iv, recipient_id, sender_id=None):
        """
        Formatting an encrypted message
        """
        message_data = {
            "type": MessageFormatter.ENCRYPTED_MESSAGE,
            "version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "recipient": recipient_id,
            "sender": sender_id,
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }

        json_data = json.dumps(message_data, indent=2)
        encoded_data = base64.b64encode(json_data.encode()).decode()

        message = f"""-----BEGIN PGP MESSAGE-----
Version: Custom PGP Implementation 1.0

{MessageFormatter._chunk_base64(encoded_data)}
-----END PGP MESSAGE-----"""

        return message

    @staticmethod
    def format_signed_message(message, signature, signer_id):
        """
        Format a signed message
        """
        message_data = {
            "type": MessageFormatter.SIGNED_MESSAGE,
            "version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "signer": signer_id,
            "message": base64.b64encode(message).decode(),
            "signature": base64.b64encode(signature).decode()
        }

        json_data = json.dumps(message_data, indent=2)
        encoded_data = base64.b64encode(json_data.encode()).decode()

        formatted = f"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{MessageFormatter._chunk_base64(encoded_data)}
-----END PGP SIGNED MESSAGE-----"""

        return formatted

    @staticmethod
    def format_encrypted_signed_message(encrypted_aes_key, encrypted_data, iv, signature, recipient_id, sender_id):
        """
        Format an encrypted and signed message
        """
        message_data = {
            "type": MessageFormatter.ENCRYPTED_SIGNED_MESSAGE,
            "version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "recipient": recipient_id,
            "sender": sender_id,
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode(),
            "signature": base64.b64encode(signature).decode()
        }

        json_data = json.dumps(message_data, indent=2)
        encoded_data = base64.b64encode(json_data.encode()).decode()

        formatted = f"""-----BEGIN PGP MESSAGE-----
Version: Custom PGP Implementation 1.0

{MessageFormatter._chunk_base64(encoded_data)}
-----END PGP MESSAGE-----"""

        return formatted

    @staticmethod
    def parse_pgp_message(pgp_message):
        """Parse a PGP formatted message"""
        try:
            lines = pgp_message.strip().split('\n')

            start_idx = None
            end_idx = None

            for i, line in enumerate(lines):
                if line.startswith("-----BEGIN PGP"):
                    start_idx = i + 1
                elif line.startswith("-----END PGP"):
                    end_idx = i
                    break

            if start_idx is None or end_idx is None:
                raise ValueError("Invalid PGP message format")

            base64_lines = []
            for i in range(start_idx, end_idx):
                line = lines[i].strip()
                if line and not line.startswith("Version:") and not line.startswith("Hash:"):
                    base64_lines.append(line)

            base64_data = ''.join(base64_lines)
            json_data = base64.b64decode(base64_data).decode('utf-8')

            message_data = json.loads(json_data)

            decoded_data = message_data.copy()

            base64_fields = ["encrypted_key", "encrypted_data", "iv", "message", "signature"]
            for field in base64_fields:
                if field in decoded_data:
                    decoded_data[field] = base64.b64decode(decoded_data[field])

            return decoded_data

        except Exception as e:
            raise ValueError(f"Failed to parse PGP message: {e}")

    @staticmethod
    def _chunk_base64(data, chunk_size=64):
        """Split base64 data into readable chunks"""
        return '\n'.join(data[i:i + chunk_size] for i in range(0, len(data), chunk_size))

    @staticmethod
    def save_message_to_file(message, filename):
        """Save PGP message to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(message)
        print(f"Message saved to: {filename}")

    @staticmethod
    def load_message_from_file(filename):
        """Load a PGP message from file"""
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()