# Secure File Sharing System

A Python-based secure file-sharing application that allows authenticated users to upload and download files securely.

## Features

- User authentication
- File encryption using Fernet symmetric encryption
- Secure file upload and download
- SHA-256 integrity verification
- Client-server communication using Python sockets

## Technologies Used

- Python
- Socket Programming
- Cryptography (Fernet)
- SHA-256 Hashing

## Project Structure

- `client.py` — Client application
- `server.py` — Server application
- `auth.py` — Authentication module
- `crypto_utils.py` — Encryption and integrity utilities
- `requirements.txt` — Required Python packages

## Installation

1. Clone this repository.
2. Install dependencies:

   `pip install -r requirements.txt`

3. Start the server:

   `python3 server.py`

4. In another terminal, run the client:

   `python3 client.py`

## Security Note

Keep encryption keys, passwords, environment files, and private user data out of public repositories. Use only test data when evaluating this project.

## Author

GitHub: [@kjyot](https://github.com/kjyot)
