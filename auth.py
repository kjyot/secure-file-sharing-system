import hashlib
import json
import os

USERS_FILE = "users.json"


def hash_password(password):
    """Generate SHA-256 hash for a password."""
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    """Load registered users from users.json."""
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as file:
        return json.load(file)


def save_users(users):
    """Save users to users.json."""
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


def register_user(username, password):
    """Register a new user."""
    users = load_users()

    if username in users:
        return False, "Username already exists."

    users[username] = hash_password(password)
    save_users(users)

    return True, "Registration successful."


def authenticate_user(username, password):
    """Authenticate an existing user."""
    users = load_users()

    if username not in users:
        return False

    return users[username] == hash_password(password)


if __name__ == "__main__":
    print("Secure File Sharing - Authentication Module")

    username = input("Enter username: ")
    password = input("Enter password: ")

    success, message = register_user(username, password)

    if success:
        print(message)
    else:
        print(message)
