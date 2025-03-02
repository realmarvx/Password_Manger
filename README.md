# Secure Password Manager

This project is a **Secure Password Manager** developed in Python.

## Features

- **Password Encryption and Decryption**: I implemented the password encryption and decryption system using the **Fernet encryption method** from the `cryptography` library.
  
- **User Authentication**: The login system uses **bcrypt** for secure password hashing and verification. The login serves as a "master key" for the user, granting access to all stored passwords after authentication.

- **Master Key Reset**: A feature to reset the master key password, ensuring security in case the user needs to change their credentials.

- **Password Storage and Retrieval**: Passwords are stored securely in a **JSON file format**. All passwords are encrypted before being stored to maintain confidentiality and integrity.

- **Lockout Mechanism**: A lockout feature is implemented after multiple failed login attempts, enhancing the security of the system.

- **Text-Based Interface**: The application provides a user-friendly text-based menu to manage passwords. It supports storing, retrieving, and resetting passwords.

## How it Works

1. **Password Storage**: Users can store passwords securely for different services. Each password is encrypted and saved in a JSON file.

2. **Password Retrieval**: The stored passwords can be retrieved after authentication, and they are decrypted when accessed.

3. **Login System**: The user needs to authenticate using a login password before gaining access to the password manager.

4. **Password Reset**: If the user needs to reset the login password, they can do so through the system.

## Installation

### Dependencies

This project requires the following libraries to be installed:

- `cryptography`
- `bcrypt`

To install these dependencies, use the following commands:

```bash
pip install cryptography
pip install bcrypt
