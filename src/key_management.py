import os
import json
from datetime import datetime
from crypto_utils import CryptoUtils


class KeyManager:
    """Manages RSA/PGP-style key generation, storage and loading."""

    def __init__(self, keys_directory="keys"):
        self.keys_directory = keys_directory
        self._ensure_keys_directory()

    def _ensure_keys_directory(self):
        """Ensure that keys directory exists."""
        os.makedirs(self.keys_directory, exist_ok=True)

    # ------------------------------------------------------------
    # KEY GENERATION
    # ------------------------------------------------------------
    def generate_keypair(self, user_id, key_size=2048, password=None):
        """Generate a new RSA keypair and store it."""

        safe_id = self._make_safe_filename(user_id)
        print(f"Generating keypair for {user_id}...")

        # Generate keys
        private_key, public_key = CryptoUtils.generate_rsa_keypair(key_size)

        # Serialize
        private_pem = CryptoUtils.serialize_private_key(private_key, password)
        public_pem = CryptoUtils.serialize_public(public_key)

        private_path = os.path.join(self.keys_directory, f"{safe_id}_private.pem")
        public_path = os.path.join(self.keys_directory, f"{safe_id}_public.pem")
        info_path = os.path.join(self.keys_directory, f"{safe_id}_info.json")

        # Write files
        with open(private_path, "wb") as f:
            f.write(private_pem)

        with open(public_path, "wb") as f:
            f.write(public_pem)

        key_info = {
            "user_id": user_id,
            "key_size": key_size,
            "created": datetime.now().isoformat(),
            "has_password": password is not None
        }

        with open(info_path, "w") as f:
            json.dump(key_info, f, indent=2)

        print("Keypair saved.")
        return key_info

    # ------------------------------------------------------------
    # LOADING KEYS
    # ------------------------------------------------------------
    def load_private_key(self, user_id, password=None):
        safe_id = self._make_safe_filename(user_id)
        path = os.path.join(self.keys_directory, f"{safe_id}_private.pem")

        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key not found for user: {user_id}")

        with open(path, "rb") as f:
            return CryptoUtils.load_private_key(f.read(), password)

    def load_public_key(self, user_id):
        safe_id = self._make_safe_filename(user_id)
        path = os.path.join(self.keys_directory, f"{safe_id}_public.pem")

        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key not found for user: {user_id}")

        with open(path, "rb") as f:
            return CryptoUtils.load_public_key(f.read())

    # ------------------------------------------------------------
    # EXPORT / IMPORT
    # ------------------------------------------------------------
    def export_public_key(self, user_id, output_file=None):
        safe_id = self._make_safe_filename(user_id)
        public_path = os.path.join(self.keys_directory, f"{safe_id}_public.pem")

        if not os.path.exists(public_path):
            raise FileNotFoundError("Public key not found.")

        if output_file is None:
            output_file = f"{safe_id}_public_export.pem"

        with open(public_path, "rb") as src, open(output_file, "wb") as dst:
            dst.write(src.read())

        print(f"Public key exported to {output_file}")
        return output_file

    def import_public_key(self, user_id, key_file):
        if not os.path.exists(key_file):
            raise FileNotFoundError("Provided key file does not exist.")

        safe_id = self._make_safe_filename(user_id)
        public_path = os.path.join(self.keys_directory, f"{safe_id}_public.pem")
        info_path = os.path.join(self.keys_directory, f"{safe_id}_info.json")

        with open(key_file, "rb") as f:
            key_data = f.read()

        # Validate the key file
        try:
            CryptoUtils.load_public_key(key_data)
        except Exception as e:
            raise ValueError(f"Invalid public key file: {e}")

        # Save imported key
        with open(public_path, "wb") as f:
            f.write(key_data)

        key_info = {
            "user_id": user_id,
            "imported": datetime.now().isoformat(),
            "source_file": key_file
        }

        with open(info_path, "w") as f:
            json.dump(key_info, f, indent=2)

        print(f"Public key imported for {user_id}")
        return key_info

    # ------------------------------------------------------------
    # LIST / DELETE
    # ------------------------------------------------------------
    def list_keys(self):
        """Return info about all keys in the directory."""
        keys = []

        for filename in os.listdir(self.keys_directory):
            if not filename.endswith("_info.json"):
                continue

            info_path = os.path.join(self.keys_directory, filename)

            try:
                with open(info_path, "r") as f:
                    info = json.load(f)

                safe_id = self._make_safe_filename(info["user_id"])
                private_path = os.path.join(self.keys_directory, f"{safe_id}_private.pem")
                public_path = os.path.join(self.keys_directory, f"{safe_id}_public.pem")

                info["has_private_key"] = os.path.exists(private_path)
                info["has_public_key"] = os.path.exists(public_path)

                keys.append(info)

            except Exception as e:
                print(f"Error reading {filename}: {e}")

        return keys

    def delete_keypair(self, user_id):
        safe_id = self._make_safe_filename(user_id)

        files = [
            f"{safe_id}_private.pem",
            f"{safe_id}_public.pem",
            f"{safe_id}_info.json"
        ]

        deleted = 0

        for file in files:
            path = os.path.join(self.keys_directory, file)
            if os.path.exists(path):
                os.remove(path)
                deleted += 1

        if deleted == 0:
            print(f"No key files found for {user_id}")
        else:
            print(f"Deleted {deleted} files for {user_id}")

    # ------------------------------------------------------------
    @staticmethod
    def _make_safe_filename(user_id):
        """Convert user ID to a safe filename (no special chars)."""
        safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."

        return "".join(c if c in safe else "_" for c in user_id)
