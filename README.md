# Password Keeper

## Overview

Password Keeper is a secure application built using Python's Tkinter library that allows users to store and manage their passwords safely. The application encrypts user data using the Fernet symmetric encryption method, ensuring that sensitive information remains protected. Users can create new password lists, open existing ones, and manage their entries with ease.

## Features

- **Secure Password Storage**: Encrypts passwords using a user-defined password and a randomly generated salt.
- **User -Friendly Interface**: Intuitive GUI built with Tkinter, making it easy to navigate and manage passwords.
- **Search Functionality**: Quickly find password entries using a search bar.
- **Virtual Keyboard**: A virtual keyboard to enhance security by preventing keylogging.
- **CRUD Operations**: Create, Read, Update, and Delete password entries.
- **Data Persistence**: Saves encrypted password data in JSON format.

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/SDevRami/Password_Keeper.git
   cd Password_Keeper
   
   ```
2. Install the required packages:

   ```
   pip install cryptography
   
   ```
3. Run the application:

   ```
   python password_keeper.py
   
   ```

## Usage

1. **Open Existing File**: Click on "Open Existing File" to load a previously saved password list. You will be prompted to enter the password used for encryption.
2. **Create New Password List**: Click on "Create New Password List" to start a new password file. You will need to set a password for encryption.
3. **Add Password Item**: Fill in the form with the title, description, email, and password, then click "Add" to save the entry.
4. **Search**: Use the search bar to filter through your password entries.
5. **Edit/Delete**: Click on the "edit" or "delete" buttons next to each entry to modify or remove it.

## Code Structure

- **PasswordKeeperApp**: The main class that initializes the application and manages the UI and functionality.
- **create_start_page**: Sets up the initial page with options to open or create a password file.
- **create_main_page**: Constructs the main interface for managing password entries.
- **add_password_item**: Handles the addition of new password entries.
- **save_data**: Encrypts and saves the password data to a file.
- **open_existing_file**: Loads and decrypts an existing password file.
- **edit_item**: Allows users to modify existing password entries.
- **delete_item**: Removes a password entry after user confirmation.

## Security

The application uses the following security measures:

- **Encryption**: Passwords are encrypted using the Fernet symmetric encryption method.
- **Key Derivation**: A key is derived from the user-provided password using PBKDF2 with a random salt to enhance security.
- **Data Protection**: Password data is stored in an encrypted format, ensuring that even if the file is accessed, the data remains secure.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

## License

This project is licensed under the GNU GENERAL PUBLIC LICENSE License. See the [LICENSE]

## Acknowledgments

- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI framework.
- [Cryptography](https://cryptography.io/en/latest/) for secure encryption methods.
