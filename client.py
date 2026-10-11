import socket
import os
import getpass

from crypto_utils import (
    load_or_create_key,
    encrypt_data,
    decrypt_data,
    calculate_sha256
)

HOST = "127.0.0.1"
PORT = 5000


def send_message(client_socket, message):
    data = message.encode("utf-8")

    client_socket.sendall(
        len(data).to_bytes(4, "big")
    )

    client_socket.sendall(data)


def receive_exact(client_socket, size):
    data = b""

    while len(data) < size:

        chunk = client_socket.recv(
            min(4096, size - len(data))
        )

        if not chunk:
            raise ConnectionError(
                "Server disconnected."
            )

        data += chunk

    return data


def receive_message(client_socket):
    length_bytes = receive_exact(
        client_socket,
        4
    )

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
    client_socket.sendall(
        len(data).to_bytes(4, "big")
    )

    client_socket.sendall(data)


def receive_bytes(client_socket):
    length_bytes = receive_exact(
        client_socket,
        4
    )

    length = int.from_bytes(
        length_bytes,
        "big"
    )

    return receive_exact(
        client_socket,
        length
    )


def login(client_socket):

    response = receive_message(
        client_socket
    )

    if response != "USERNAME":
        print("Unexpected server response.")
        return False

    username = input(
        "Username: "
    )

    send_message(
        client_socket,
        username
    )

    response = receive_message(
        client_socket
    )

    if response != "PASSWORD":
        print("Unexpected server response.")
        return False

    password = getpass.getpass(
        "Password: "
    )

    send_message(
        client_socket,
        password
    )

    response = receive_message(
        client_socket
    )

    if response == "AUTH_SUCCESS":

        print(
            "\n✓ Authentication successful!"
        )

        print(
            f"Welcome, {username}!"
        )

        return True

    print(
        "\n✗ Authentication failed."
    )

    return False


def upload_file(client_socket):

    print("\n--- Upload File ---")

    file_path = input(
        "Enter file path: "
    ).strip()

    if not os.path.isfile(file_path):

        print(
            "✗ File not found."
        )

        return

    filename = os.path.basename(
        file_path
    )

    response = receive_message(
        client_socket
    )

    if response != "FILENAME":

        print(
            "Unexpected server response."
        )

        return

    send_message(
        client_socket,
        filename
    )

    response = receive_message(
        client_socket
    )

    if response != "READY_FOR_FILE":

        print(
            f"Server response: {response}"
        )

        return

    with open(
        file_path,
        "rb"
    ) as file:

        original_data = file.read()

    print(
        f"Original file size: "
        f"{len(original_data)} bytes"
    )

    # Encrypt before transmission
    key = load_or_create_key()

    encrypted_data = encrypt_data(
        original_data,
        key
    )

    print(
        f"Encrypted file size: "
        f"{len(encrypted_data)} bytes"
    )

    # Send encrypted file
    send_bytes(
        client_socket,
        encrypted_data
    )

    response = receive_message(
        client_socket
    )

    if response.startswith(
        "UPLOAD_SUCCESS|"
    ):

        file_hash = response.split(
            "|",
            1
        )[1]

        local_hash = calculate_sha256(
            original_data
        )

        print(
            "\n✓ File uploaded successfully!"
        )

        print(
            f"File: {filename}"
        )

        print(
            f"SHA-256: {file_hash}"
        )

        if file_hash == local_hash:

            print(
                "✓ Integrity verification successful"
            )

        else:

            print(
                "✗ Integrity verification failed"
            )

    else:

        print(
            f"✗ Upload failed: {response}"
        )


def download_file(client_socket):

    print("\n--- Download File ---")

    filename = input(
        "Enter filename to download: "
    ).strip()

    response = receive_message(
        client_socket
    )

    if response != "FILENAME":

        print(
            "Unexpected server response."
        )

        return

    send_message(
        client_socket,
        filename
    )

    response = receive_message(
        client_socket
    )

    if response == "FILE_NOT_FOUND":

        print(
            "✗ File not found on server."
        )

        return

    if response == "METADATA_NOT_FOUND":

        print(
            "✗ File metadata not found."
        )

        return

    if response == "DECRYPTION_FAILED":

        print(
            "✗ Server could not decrypt the file."
        )

        return

    if response == "INTEGRITY_FAILED":

        print(
            "✗ Server integrity verification failed."
        )

        return

    if response != "READY_FOR_FILE":

        print(
            f"Unexpected response: {response}"
        )

        return

    encrypted_data = receive_bytes(
        client_socket
    )

    print(
        f"Received encrypted data: "
        f"{len(encrypted_data)} bytes"
    )

    # Decrypt locally
    key = load_or_create_key()

    try:

        original_data = decrypt_data(
            encrypted_data,
            key
        )

    except Exception:

        print(
            "✗ Decryption failed."
        )

        return

    # Calculate SHA-256
    local_hash = calculate_sha256(
        original_data
    )

    response = receive_message(
        client_socket
    )

    if not response.startswith(
        "DOWNLOAD_SUCCESS|"
    ):

        print(
            f"✗ Download failed: {response}"
        )

        return

    server_hash = response.split(
        "|",
        1
    )[1]

    # Save file
    download_folder = "downloads"

    os.makedirs(
        download_folder,
        exist_ok=True
    )

    output_path = os.path.join(
        download_folder,
        filename
    )

    with open(
        output_path,
        "wb"
    ) as file:

        file.write(
            original_data
        )

    print(
        "\n✓ File downloaded successfully!"
    )

    print(
        f"Saved to: {output_path}"
    )

    print(
        f"SHA-256: {local_hash}"
    )

    if local_hash == server_hash:

        print(
            "✓ Integrity verification successful"
        )

    else:

        print(
            "✗ Integrity verification failed"
        )


def show_menu():

    print(
        "\n" + "=" * 45
    )

    print(
        "       SECURE FILE SHARING SYSTEM"
    )

    print(
        "=" * 45
    )

    print(
        "1. Upload File"
    )

    print(
        "2. Download File"
    )

    print(
        "3. Quit"
    )

    print(
        "=" * 45
    )


def start_client():

    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:

        client_socket.connect(
            (HOST, PORT)
        )

        print(
            "\n✓ Connected to Secure File Sharing Server."
        )

        if not login(client_socket):

            client_socket.close()

            return

        while True:

            response = receive_message(
                client_socket
            )

            if response != "MENU":

                print(
                    f"Unexpected server response: "
                    f"{response}"
                )

                break

            show_menu()

            choice = input(
                "Choose an option: "
            ).strip()

            if choice == "1":

                send_message(
                    client_socket,
                    "UPLOAD"
                )

                upload_file(
                    client_socket
                )

            elif choice == "2":

                send_message(
                    client_socket,
                    "DOWNLOAD"
                )

                download_file(
                    client_socket
                )

            elif choice == "3":

                send_message(
                    client_socket,
                    "QUIT"
                )

                response = receive_message(
                    client_socket
                )

                if response == "GOODBYE":

                    print(
                        "\nGoodbye!"
                    )

                break

            else:

                print(
                    "✗ Invalid option."
                )

    except ConnectionRefusedError:

        print(
            "✗ Could not connect to server."
        )

        print(
            "Make sure server.py is running."
        )

    except Exception as error:

        print(
            f"✗ Client error: {error}"
        )

    finally:

        client_socket.close()

        print(
            "Client disconnected."
        )


if __name__ == "__main__":

    start_client()
