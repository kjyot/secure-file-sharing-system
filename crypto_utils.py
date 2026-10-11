from cryptography.fernet import Fernet
import hashlib
import base64
import os

KEY_FILE = "secret.key"


def generate_key():
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key()


def load_or_create_key():
    """Load the existing encryption key or create a new one."""

    if not os.path.exists(KEY_FILE):
        key = generate_key()

        with open(KEY_FILE, "wb") as file:
            file.write(key)

        return key

    with open(KEY_FILE, "rb") as file:
        return file.read()


def encrypt_data(data, key):
    """Encrypt data using Fernet authenticated encryption."""
    cipher = Fernet(key)
    return cipher.encrypt(data)


def decrypt_data(data, key):
    """Decrypt and authenticate encrypted data."""
    cipher = Fernet(key)
    return cipher.decrypt(data)


def calculate_sha256(data):
    """Calculate SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def encode_data(data):
    """Encode binary data as Base64."""
    return base64.b64encode(data).decode("utf-8")


def decode_data(data):
    """Decode Base64 data back to bytes."""
    return base64.b64decode(data.encode("utf-8"))


if __name__ == "__main__":

    print("Secure File Sharing - Cryptography Module")

    key = load_or_create_key()

    original_data = b"Hello Secure File Sharing!"

    encrypted = encrypt_data(
        original_data,
        key
    )

    decrypted = decrypt_data(
        encrypted,
        key
    )

    original_hash = calculate_sha256(
        original_data
    )

    decrypted_hash = calculate_sha256(
        decrypted
    )

    print("\nOriginal data:")
    print(original_data.decode())

    print("\nEncrypted data:")
    print(encrypted)

    print("\nDecrypted data:")
    print(decrypted.decode())

    print("\nOriginal SHA-256:")
    print(original_hash)

    print("\nDecrypted SHA-256:")
    print(decrypted_hash)

    if original_hash == decrypted_hash:
        print("\n✓ Integrity verification successful")
    else:
        print("\n✗ Integrity verification failed")
