"""
Custom PGP: Pretty Good Privacy implementation package
"""

from .pgp_core import PGP
from .key_management import KeyManager
from .crypto_utils import CryptoUtils
from .message_format import MessageFormatter

__version__ = "1.0.0"
__author__ = "Chukwuebuka Anselm Icheku"
__all__ = ["PGP", "KeyManager", "CryptoUtils", "MessageFormatter"]

# Optional: prevent accidental direct execution
if __name__ == "__main__":
    print("This is a package. Use 'python -m src.pgp_core' to run the PGP implementation.")