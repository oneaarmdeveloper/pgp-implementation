# Custom PGP Implementation

A Python-based educational implementation of Pretty Good Privacy (PGP). Supports key generation, message encryption/decryption, and digital signatures.

---

## Features

* Generate public/private key pairs
* Encrypt messages for recipients
* Decrypt messages
* Sign messages digitally
* Verify digital signatures
* Hybrid encryption (AES + RSA)
* PGP-like message formatting

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/pgp-implementation.git
cd pgp-implementation
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install dependencies (if any):

```bash
pip install -r requirements.txt
```

> **Note:** The `keys/` folder and `venv/` are ignored in Git. Your keys will be generated locally when running the demo.

---

## Usage

Run the demo script:

```bash
python -m src.pgp_core
```

It will generate key pairs for users, encrypt a sample message, and decrypt it.

---

## Project Structure

```
pgp-implementation/
├── src/
│   ├── __init__.py
│   ├── pgp_core.py
│   ├── key_management.py
│   ├── crypto_utils.py
│   └── message_format.py
├── README.md
```

---

## Author

Chukwuebuka Anselm Icheku

---

## License

MIT License
