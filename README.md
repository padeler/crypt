# Crypt

Store your secrets in the crypt. 
The crypt comes with a cool crypt-shell interface for managing your encrypted information.

## Overview

The database file is encrypted using AES-128 symmetric encryption via the Fernet implementation.
For more details about the encryption specification, see: https://github.com/fernet/spec/blob/master/Spec.md

## Features

- Secure key derivation using PBKDF2 with SHA-256
- Customizable iteration count for PBKDF2 (defaults to 310,000 as recommended by OWASP)
- Interactive shell interface for managing encrypted data
- Support for key-value pairs with multiple values per key
- Password generation capabilities
- File locking to prevent database corruption

## Dependencies

- Python 3.6+
- cryptography
- clize

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the crypt shell:

```bash
./crypt.py [database_file]
```

### Available Commands

Once in the shell, you can use the following commands:

- `open <filename>` - Open an existing database or create a new one
- `create <filename>` - Create a new database
- `list [key]` - List all keys or a specific key
- `insert <key> <value1> [value2...]` - Insert a new key with values
- `update <key> <value1> [value2...]` - Update an existing key with new values
- `append <key> <value1> [value2...]` - Append values to an existing key
- `delete <key>` - Delete a key and its values
- `generate [length]` - Generate a random password
- `upgrade [iterations]` - Upgrade database to use stronger encryption settings
- `password` - Change the database password
- `quit` - Exit the program

## Advanced Usage

### Customizing Key Derivation Iterations

You can specify the number of iterations for PBKDF2 key derivation:

```python
# Use 500,000 iterations for PBKDF2 (even stronger security)
./crypt.py --iterations=500000 mydatabase.db
```

### Upgrading Database Security

To upgrade an existing database to use more secure key derivation:

```
> open mydatabase.db
Password: ******
> upgrade
Upgrading database from 100000 to 310000 iterations...
Database upgraded successfully.
```

## Testing

To run the test suite:

```bash
./tests/run_tests.py
```

Or run individual test files:

```bash
python -m unittest tests/test_crypt.py
python -m unittest tests/test_shell.py
```

