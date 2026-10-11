import os
import socket
import threading
import json

from auth import authenticate_user
from crypto_utils import (
    load_or_create_key,
    encrypt_data,
    decrypt_data,
    calculate_sha256
)

HOST = "127.0.0.1"
PORT = 5000

SHARED_FOLDER = "shared_files"

ENCRYPTION_KEY = load_or_create_key()

os.makedirs(SHARED_FOLDER, exist_ok=True)


def send_message(client_socket, message):
    """Send a text message with a 4-byte length prefix."""

    data = message.encode("utf-8")

    client_socket.sendall(
        len(data).to_bytes(4, "big")
    )

    client_socket.sendall(data)


def receive_message(client_socket):
    """Receive a length-prefixed text message."""

    length_bytes = receive_exact(
        client_socket,
        4
    )

    if not length_bytes:
        return None

    length = int.from_bytes(
        length_bytes,
        "big"
    )

    data = receive_exact(
        client_socket,
        length
    )

    return data.decode("utf-8")


def send_bytes(client_socket, data):
    """Send binary data with a 4-byte length prefix."""

    client_socket.sendall(
        len(data).to_bytes(4, "big")
    )

    client_socket.sendall(data)


def receive_bytes(client_socket):
    """Receive length-prefixed binary data."""

    length_bytes = receive_exact(
        client_socket,
        4
    )

    if not length_bytes:
        return None

    length = int.from_bytes(
        length_bytes,
        "big"
    )

    return receive_exact(
        client_socket,
        length
    )


def receive_exact(client_socket, size):
    """Receive exactly the requested number of bytes."""

    data = b""

    while len(data) < size:

        chunk = client_socket.recv(
            min(4096, size - len(data))
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed during transfer."
            )

        data += chunk

    return data


def authenticate_client(client_socket):
    """Authenticate the connected client."""

    send_message(
        client_socket,
        "USERNAME"
    )

    username = receive_message(
        client_socket
    )

    send_message(
        client_socket,
        "PASSWORD"
    )

    password = receive_message(
        client_socket
    )

    if authenticate_user(
        username,
        password
    ):

        send_message(
            client_socket,
            "AUTH_SUCCESS"
        )

        print(
            f"[+] User authenticated: {username}"
        )

        return username

    send_message(
        client_socket,
        "AUTH_FAILED"
    )

    print(
        f"[-] Authentication failed: {username}"
    )

    return None


def receive_file(client_socket, username):
    """Receive an encrypted file from the client."""

    send_message(
        client_socket,
        "FILENAME"
    )

    filename = receive_message(
        client_socket
    )

    filename = os.path.basename(
        filename
    )

    if not filename:
        send_message(
            client_socket,
            "INVALID_FILENAME"
        )
        return

    send_message(
        client_socket,
        "READY_FOR_FILE"
    )

    # Receive encrypted file
    encrypted_data = receive_bytes(
        client_socket
    )

    if not encrypted_data:
        send_message(
            client_socket,
            "TRANSFER_FAILED"
        )
        return

    print(
        f"[+] Encrypted file received: "
        f"{filename}"
    )

    # Decrypt file
    try:

        file_data = decrypt_data(
            encrypted_data,
            ENCRYPTION_KEY
        )

    except Exception:

        send_message(
            client_socket,
            "DECRYPTION_FAILED"
        )

        return

    # Calculate SHA-256 of original file
    file_hash = calculate_sha256(
        file_data
    )

    # Store encrypted file
    encrypted_file_path = os.path.join(
        SHARED_FOLDER,
        filename + ".enc"
    )

    with open(
        encrypted_file_path,
        "wb"
    ) as file:

        file.write(
            encrypted_data
        )

    # Store metadata
    metadata = {
        "filename": filename,
        "owner": username,
        "size": len(file_data),
        "encrypted_size": len(encrypted_data),
        "sha256": file_hash
    }

    metadata_path = os.path.join(
        SHARED_FOLDER,
        filename + ".json"
    )

    with open(
        metadata_path,
        "w"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4
        )

    send_message(
        client_socket,
        f"UPLOAD_SUCCESS|{file_hash}"
    )

    print(
        f"[+] File uploaded by {username}: "
        f"{filename}"
    )

    print(
        f"    SHA-256: {file_hash}"
    )


def send_file(client_socket, username):
    """Send an encrypted file to the client."""

    send_message(
        client_socket,
        "FILENAME"
    )

    filename = receive_message(
        client_socket
    )

    filename = os.path.basename(
        filename
    )

    encrypted_file_path = os.path.join(
        SHARED_FOLDER,
        filename + ".enc"
    )

    metadata_path = os.path.join(
        SHARED_FOLDER,
        filename + ".json"
    )

    if not os.path.exists(
        encrypted_file_path
    ):

        send_message(
            client_socket,
            "FILE_NOT_FOUND"
        )

        return

    if not os.path.exists(
        metadata_path
    ):

        send_message(
            client_socket,
            "METADATA_NOT_FOUND"
        )

        return

    with open(
        encrypted_file_path,
        "rb"
    ) as file:

        encrypted_data = file.read()

    with open(
        metadata_path,
        "r"
    ) as file:

        metadata = json.load(
            file
        )

    # Decrypt to verify integrity before sending
    try:

        file_data = decrypt_data(
            encrypted_data,
            ENCRYPTION_KEY
        )

    except Exception:

        send_message(
            client_socket,
            "DECRYPTION_FAILED"
        )

        return

    calculated_hash = calculate_sha256(
        file_data
    )

    # Verify stored metadata
    if calculated_hash != metadata["sha256"]:

        send_message(
            client_socket,
            "INTEGRITY_FAILED"
        )

        print(
            f"[!] Integrity verification failed: "
            f"{filename}"
        )

        return

    send_message(
        client_socket,
        "READY_FOR_FILE"
    )

    # Send encrypted file
    send_bytes(
        client_socket,
        encrypted_data
    )

    send_message(
        client_socket,
        f"DOWNLOAD_SUCCESS|{calculated_hash}"
    )

    print(
        f"[+] File downloaded by {username}: "
        f"{filename}"
    )


def handle_client(
    client_socket,
    client_address
):
    """Handle one client connection."""

    print(
        f"[+] Client connected: "
        f"{client_address}"
    )

    try:

        username = authenticate_client(
            client_socket
        )

        if not username:
            client_socket.close()
            return

        while True:

            send_message(
                client_socket,
                "MENU"
            )

            command = receive_message(
                client_socket
            )

            if command == "UPLOAD":

                receive_file(
                    client_socket,
                    username
                )

            elif command == "DOWNLOAD":

                send_file(
                    client_socket,
                    username
                )

            elif command == "QUIT":

                send_message(
                    client_socket,
                    "GOODBYE"
                )

                break

            else:

                send_message(
                    client_socket,
                    "INVALID_COMMAND"
                )

    except ConnectionResetError:

        print(
            f"[-] Client disconnected: "
            f"{client_address}"
        )

    except Exception as error:

        print(
            f"[!] Client error "
            f"{client_address}: {error}"
        )

    finally:

        client_socket.close()

        print(
            f"[-] Connection closed: "
            f"{client_address}"
        )


def start_server():
    """Start the secure file-sharing server."""

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind(
        (HOST, PORT)
    )

    server_socket.listen(5)

    print("=" * 55)
    print("        SECURE FILE SHARING SERVER")
    print("=" * 55)
    print(
        f"Server listening on "
        f"{HOST}:{PORT}"
    )
    print("Waiting for clients...")
    print("Press Ctrl+C to stop the server.")
    print("=" * 55)

    try:

        while True:

            client_socket, client_address = (
                server_socket.accept()
            )

            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    client_socket,
                    client_address
                ),
                daemon=True
            )

            client_thread.start()

            print(
                f"[+] Active client threads: "
                f"{threading.active_count() - 1}"
            )

    except KeyboardInterrupt:

        print(
            "\n[!] Server shutting down..."
        )

    finally:

        server_socket.close()

        print(
            "[+] Server stopped."
        )


if __name__ == "__main__":
    start_server()
