"""Small RSA/AES cryptography utility.

Private keys are encrypted on disk with a password. Messages use hybrid
encryption: RSA-OAEP protects an AES key and AES-GCM protects the data.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_DIR = Path(__file__).resolve().parent
KEY_DIR = APP_DIR / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "public_key.pem"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def generate_keys() -> None:
    KEY_DIR.mkdir(exist_ok=True)
    password = getpass.getpass("Password for the private key: ")
    if not password:
        print("A password is required.")
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_private_key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(encrypted_private_key)
    PUBLIC_KEY_PATH.write_bytes(public_key)
    print(f"Private key saved to {PRIVATE_KEY_PATH}")
    print(f"Public key saved to  {PUBLIC_KEY_PATH}")


def _load_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError("No private key found. Generate keys first.")
    password = getpass.getpass("Private key password: ").encode("utf-8")
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(), password=password
    )


def _load_public_key():
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError("No public key found. Generate keys first.")
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())


def encrypt_message() -> None:
    public_key = _load_public_key()
    plaintext = input("Message to encrypt: ").encode("utf-8")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    package = {"key": _b64(wrapped_key), "nonce": _b64(nonce), "data": _b64(ciphertext)}
    output_path = APP_DIR / "encrypted_message.json"
    output_path.write_text(json.dumps(package, indent=2), encoding="utf-8")
    print(f"Encrypted message saved to {output_path}")


def decrypt_message() -> None:
    private_key = _load_private_key()
    input_path = APP_DIR / "encrypted_message.json"
    if not input_path.exists():
        raise FileNotFoundError(f"Encrypted message not found: {input_path}")
    package = json.loads(input_path.read_text(encoding="utf-8"))
    aes_key = private_key.decrypt(
        _unb64(package["key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        _unb64(package["nonce"]), _unb64(package["data"]), None
    )
    print(f"Decrypted message: {plaintext.decode('utf-8')}")


def main() -> None:
    actions = {
        "1": ("Generate private/public key pair", generate_keys),
        "2": ("Encrypt a message with the public key", encrypt_message),
        "3": ("Decrypt the message with the private key", decrypt_message),
        "4": ("Exit", None),
    }
    while True:
        print("\nCryptoSoft")
        for number, (description, _) in actions.items():
            print(f"{number}. {description}")
        choice = input("Choose an option: ").strip()
        if choice == "4":
            return
        action = actions.get(choice)
        if action is None:
            print("Invalid option.")
            continue
        try:
            action[1]()
        except (
            FileNotFoundError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            InvalidTag,
        ) as error:
            print(f"Operation failed: {error}")


if __name__ == "__main__":
    main()