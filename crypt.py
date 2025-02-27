#!/usr/bin/python3
"""crypt
Create, view and maintain an encrypted db of key=value(s) pairs.

Encryption/decryption is done using the Fernet symmetric encryption spec.
https://github.com/fernet/spec/blob/master/Spec.md

Depends on the "cryptography" python package.
"""
# pyright: reportShadowedImports=none
# pyright: reportMissingDocstring=None
from typing import Dict, List, Tuple, Optional, Any, Union
import base64
import datetime
import getpass
import json
import os
import string
import random
import sys
import fcntl
import subprocess

from cmd import Cmd
import shlex

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from clize import run

VERSION = "crypt v0.6"
SALT_LEN = 16
LEGACY_ITERATIONS = 100000  # Original iteration count
DEFAULT_ITERATIONS = 310000  # OWASP recommended minimum


def _gen_key(
    password: str, salt: bytes = None, iterations: int = DEFAULT_ITERATIONS
) -> Tuple[bytes, bytes]:
    """
    Generate a key from a password and salt using PBKDF2.

    Args:
        password: The password to derive the key from
        salt: Optional salt bytes. If None, generates random salt.
        iterations: Number of PBKDF2 iterations to use for key derivation

    Returns:
        Tuple of (key, salt) where key is the derived key and salt is the salt used
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def _write_db(
    password: str,
    db_dict: Dict[str, Any],
    filename: str,
    iterations: int = DEFAULT_ITERATIONS,
) -> None:
    """
    Write an encrypted database to a file.

    Args:
        password: The password to encrypt the database with
        db_dict: The database dictionary to encrypt
        filename: The file to write the encrypted database to
        iterations: Number of PBKDF2 iterations to use for key derivation

    Raises:
        IOError: If the file cannot be written to
    """
    key, salt = _gen_key(password, iterations=iterations)

    # Store the iterations used for this database file
    db_dict["iterations"] = iterations

    ts = datetime.datetime.now()
    db_dict["modified"] = str(ts)

    # convert db_dict to json
    db_json = json.dumps(db_dict)

    # encrypt with key and Fernet
    fernet = Fernet(key)
    db_crypt = fernet.encrypt(db_json.encode())

    with open(filename, "wb") as f:
        # Acquire an exclusive lock before writing
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            f.write(salt)
            f.write(db_crypt)
            # Release the lock when done
            fcntl.flock(f, fcntl.LOCK_UN)
        except IOError:
            raise IOError(f"Cannot write to {filename}. File is locked by another process.")


def _load_db(
    password: str, filename: str, iterations: int = LEGACY_ITERATIONS
) -> Dict[str, Any]:
    """
    Load and decrypt a database from a file.

    Args:
        password: The password to decrypt the database with
        filename: The file to read the encrypted database from
        iterations: Number of PBKDF2 iterations to use for key derivation

    Returns:
        The decrypted database dictionary

    Raises:
        IOError: If the file cannot be read or is corrupted
        ValueError: If the password is incorrect
    """
    with open(filename, "rb") as f:
        # Acquire a shared lock for reading
        try:
            fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
            salt = f.read(SALT_LEN)  # read salt
            if len(salt) != SALT_LEN:
                raise IOError("Corrupted/invalid db file. Failed to read salt")

            db_crypt = f.read()  # read full db
            # Release the lock when done reading
            fcntl.flock(f, fcntl.LOCK_UN)
        except IOError:
            raise IOError(f"Cannot read from {filename}. File is locked by another process.")

        # compute key with specified iterations
        key, salt = _gen_key(password, salt, iterations)
        fernet = Fernet(key)

        try:
            # decrypt
            db_json = fernet.decrypt(db_crypt)
        except Exception as exc:
            raise ValueError("Decrypt failed. Check your password.") from exc

    db_dict = json.loads(db_json)
    return db_dict


class CryptShell(Cmd):
    """
    Shell interface for the db operations
    """

    def __init__(self) -> None:
        """Initialize the CryptShell with empty database attributes."""
        super().__init__()
        self.db_filename: Optional[str] = None
        self.password: Optional[str] = None
        self.db_dict: Optional[Dict[str, Any]] = None

    def do_open(self, args: str, iterations: int = LEGACY_ITERATIONS) -> Optional[bool]:
        """
        Open a db, load everything in memory.

        Args:
            args: The db filename as a string
            iterations: Number of PBKDF2 iterations to use for key derivation

        Returns:
            None on success, False on failure
        """
        try:
            args_list = shlex.split(args)
            if not args_list:
                print("Error: Missing database filename")
                return False

            self.db_filename = args_list[0]
            self.prompt = "Crypt [] >>> "

            if not os.path.exists(self.db_filename):
                print(f"Database file {self.db_filename} does not exist.")
                if self.do_create(args_list, iterations=DEFAULT_ITERATIONS) is False:
                    return False

            print(f"Opening database {self.db_filename}")
            filename = self.db_filename
            password = getpass.getpass("Password: ")
            db_dict = _load_db(password, filename, iterations)

            # Store the iterations used
            stored_iterations = db_dict.get("iterations", LEGACY_ITERATIONS)
            print(
                f"Opened db file {filename}, DB version string is \"{db_dict.get('version', 'N/A')}\""
            )
            print(f"Created on {db_dict.get('created', 'N/A')}")
            print(f"Modified on {db_dict.get('modified', 'N/A')}")
            print(f"Using {stored_iterations} iterations for key derivation")

            self.db_dict = db_dict
            self.password = password
            self.prompt = f"Crypt [{filename}] >>> "
            return None
        except IndexError:
            print("Error: Invalid arguments")
            return False

    def do_list(self, args: str) -> None:
        """
        List a key or keys to display. No arguments will print the entire db.

        Args:
            args: Space-separated list of keys to display, or empty to show all

        Returns:
            None
        """
        if self.db_dict is None:
            print("No database loaded. Use 'open' first.")
            return

        keys = shlex.split(args) if args else []

        if not keys:
            keys = list(self.db_dict.keys())

        for k in keys:
            values = self.db_dict.get(k)
            if values is not None:
                print(f"{k}: {values}")
            else:
                print(f'Key "{k}" not found.')

        return None

    def do_generate(self, args: str) -> None:
        """
        Generate a random alphanumeric string of given length.

        Args:
            args: Length of the string to generate (optional, defaults to 32)

        Returns:
            None
        """
        args_list = shlex.split(args) if args else []
        length = 32  # Default length

        if args_list:
            try:
                length = int(args_list[0])
                if length <= 0:
                    raise ValueError()
            except ValueError:
                print(f"Invalid length '{args_list[0]}'. Using default length of 32.")
                length = 32

        chars = string.ascii_letters + string.digits + "@#%&"
        random.seed(os.urandom(1024))
        value = ''.join(random.choice(chars) for i in range(length))

        print(f"Generated value (length={length}): {value}")
        return None

    def do_append(self, args: str) -> Optional[bool]:
        """
        Append values to an existing key.

        Args:
            args: Key and values to append in the format "key value1 value2..."

        Returns:
            None on success, False on failure
        """
        if self.db_dict is None or self.password is None:
            print("No database loaded. Use 'open' first.")
            return False

        args_list = shlex.split(args) if args else []

        if not args_list:
            print("Error: Missing key")
            return False

        key = args_list[0]
        if self.db_dict.get(key) is None:
            print(f"Key \"{key}\" does not exist. Use insert.")
            return False

        values = [str(v) for v in args_list[1:]]

        if not values:
            print("Error: No values provided to append")
            return False

        self.db_dict[key] += values
        _write_db(self.password, self.db_dict, self.db_filename)
        print(f"Appended new values to existing list of key \"{key}\" to db \"{self.db_filename}\"")
        return None

    def do_update(self, args):
        """
        Update the values of an existing key. Old values are deleted
        :param args: new values
        """
        args = shlex.split(args)
        key = args[0]
        if self.db_dict.get(key) is None:
            print(f"Key \"{key}\" does not exist. Use insert.")
            return False

        values = [str(v) for v in args[1:]]
        if len(values) == 0:
            print(f"No values for key {key}. This is pointless, i give up.")
            return False

        self.db_dict[key] = values
        _write_db(self.password, self.db_dict, self.db_filename)
        print(f"Updated key \"{key}\" to db \"{self.db_filename}\"")
        return None

    def do_upgrade(self, args: str) -> Optional[bool]:
        """
        Upgrade the database to use more secure encryption settings.

        Args:
            args: Optional target iterations number, defaults to DEFAULT_ITERATIONS

        Returns:
            None on success, False on failure
        """
        if self.db_dict is None or self.password is None or self.db_filename is None:
            print("No database loaded. Use 'open' first.")
            return False

        args_list = shlex.split(args) if args else []
        target_iterations = DEFAULT_ITERATIONS

        if args_list:
            try:
                target_iterations = int(args_list[0])
                if target_iterations <= 0:
                    print("Iterations must be a positive integer.")
                    return False
            except ValueError:
                print(f"Invalid iterations value: '{args_list[0]}'")
                return False

        current_iterations = self.db_dict.get("iterations", LEGACY_ITERATIONS)

        if current_iterations >= target_iterations:
            print(
                f"Database already using {current_iterations} iterations (requested: {target_iterations})."
            )
            print("No upgrade needed.")
            return None

        print(
            f"Upgrading database from {current_iterations} to {target_iterations} iterations..."
        )

        # Write the database with new iterations
        _write_db(self.password, self.db_dict, self.db_filename, target_iterations)

        print(
            f"Database upgraded successfully. Now using {target_iterations} iterations."
        )
        return None

    def do_password(self, args):
        """
        Change the password of the loaded database
        """
        if not os.path.exists(self.db_filename) or self.db_dict is None or self.password is None:
            print("No database loaded. Aborting.")
            return False

        print(f"Changing password for database {self.db_filename}")
        oldpassword = getpass.getpass("Enter old password: ")
        if oldpassword != self.password:
            print("Wrong password. Aborting.")
            return False

        password = getpass.getpass("Enter new password: ")
        password2 = getpass.getpass("Re-enter password: ")

        if password != password2:
            print("Passwords do not match.")
            return False

        self.password = password
        _write_db(self.password, self.db_dict, self.db_filename)
        print("Password changed.")
        return None

    def do_create(self, args, iterations: int = DEFAULT_ITERATIONS):
        """
        Create a new database. It will prompt for new password.
        The current db loaded is discarded. The file of the current db is not altered.

        Args:
            args: The filename for the new db
            iterations: Number of PBKDF2 iterations to use for key derivation

        Returns:
            None on success, False on failure
        """
        if isinstance(args, str):
            args_list = shlex.split(args)
            if not args_list:
                print("Error: Missing database filename")
                return False
            self.db_filename = args_list[0]
        else:
            # Handle case when args is already a list
            self.db_filename = args[0]

        if os.path.exists(self.db_filename):
            print(f"Database file {self.db_filename} already exists. Will not overwrite.")
            return False

        print(f"Creating database {self.db_filename}")
        password = getpass.getpass("Enter new password: ")
        password2 = getpass.getpass("Re-enter password: ")

        if password != password2:
            print("Passwords do not match.")
            return False

        ts = datetime.datetime.now()
        self.password = password
        self.db_dict = {
            "created": str(ts),
            "version": VERSION,
            "iterations": iterations,
        }

        print(f"Creating new db file {self.db_filename} with {iterations} iterations")
        _write_db(self.password, self.db_dict, self.db_filename, iterations)
        return None

    def do_delete(self, args):
        """
        Delete a key (and its values).
        :param key: the key to delete
        """
        args = shlex.split(args)
        key = args[0]
        value = self.db_dict.get(key, None)
        if value is None or not isinstance(value, list):
            print(f"Key \"{key}\" does not exist.")
            return False

        self.db_dict.pop(key)
        _write_db(self.password, self.db_dict, self.db_filename)
        print(f"Deleted key \"{key}\" from db \"{self.db_filename}\"")
        return None

    def do_insert(self, args):
        """
        Insert a key and one or more values.
        :param key [value1] [value2] ...: key and values
        """
        args = shlex.split(args)
        key = args[0]
        if self.db_dict.get(key) is not None:
            print(f"Key \"{key}\" already exists. Use update to overwrite")
            return False

        values = [str(v) for v in args[1:]]

        if len(values) == 0:
            print(f"No values for key {key}. This is pointless, i give up.")
            return False

        self.db_dict[key] = values
        _write_db(self.password, self.db_dict, self.db_filename)
        print(f"Added new key \"{key}\" to db \"{self.db_filename}\"")
        return None

    def do_quit(self, args):
        """Quit crypt."""
        raise SystemExit

    def do_clear(self, args):
        """
        Clear screen
        """
        if os.name == 'nt':
            subprocess.run(['cls'], shell=True, check=False)
        else:
            subprocess.run(['clear'], check=False)

    def _complete_key(self, text, line, beginidx, endidx):
        res = []
        if self.db_dict is not None:
            res = [s for s in self.db_dict.keys() if text in s and isinstance(self.db_dict[s], list)]
        return res

    def complete_list(self, text, line, beginidx, endidx):
        return self._complete_key(text, line, beginidx, endidx) 
    def complete_append(self, text, line, beginidx, endidx):
        return self._complete_key(text, line, beginidx, endidx) 
    def complete_delete(self, text, line, beginidx, endidx):
        return self._complete_key(text, line, beginidx, endidx) 
    def complete_update(self, text, line, beginidx, endidx):
        return self._complete_key(text, line, beginidx, endidx)

    def emptyline(self):
        pass

    def default(self, line):
        if line == "EOF":
            print("\n")
            self.do_quit(line)
        else:
            print("Bad command. Type \"?\" for help.")


def runner(db: str = "crypt.db", iterations: int = None) -> None:
    """
    Create, view and maintain an encrypted db of key=value(s) pairs.

    Args:
        db: Database file path
        iterations: Number of PBKDF2 iterations to use for key derivation
                   If None, uses DEFAULT_ITERATIONS

    Returns:
        None

    Exits:
        With status code 1 on error
    """
    cshell = CryptShell()

    # Use provided iterations value or the legacy value for compatibility
    load_iterations = iterations if iterations is not None else DEFAULT_ITERATIONS

    try:
        # Pass the iterations parameter to do_open
        res = cshell.do_open(db, iterations=load_iterations)

        if res is not False:  # db opened succesfully
            cshell.cmdloop(f"Crypt shell {VERSION}")

    except IOError as io_ex:
        print(f"File access error: {io_ex}")
        sys.exit(1)
    except ValueError as val_ex:
        print(f"Value error: {val_ex}")
        sys.exit(1)
    except Exception as ex:
        print(f"Error: {ex}")
        sys.exit(1)


if __name__ == '__main__':
    run(runner)
