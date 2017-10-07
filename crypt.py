#!/usr/bin/python

"""crypt

Create, view and maintain an encrypted db of key=value(s) pairs.

Encryption/decryption is done using the Fernet symmetric encryption spec.
https://github.com/fernet/spec/blob/master/Spec.md

Depends on the "cryptography" python package.

Usage:
    crypt.py [-d filename.db]

Options:
 -h, --help  show this
 -d filename.db database file name. If omitted, default is crypt.db
"""
import base64
import datetime
import getpass
import json
import os
import string
import random
from optparse import OptionParser

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERSION = "crypt v0.1"
SALT_LEN = 16


def create_parser():
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("-d", dest="db", metavar="file.db", help="Database file. Default is crypt.db", default="crypt.db")
    return parser


def _gen_key(password, salt=os.urandom(SALT_LEN)):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # print("Key %d %s" %(len(key), key))
    # print("Salt %d %s" %(len(salt), salt))
    return key, salt


def _write_db(password, db_dict, filename):
    key, salt = _gen_key(password)

    ts = datetime.datetime.now()
    db_dict["modified"] = str(ts)

    # convert db_dict to json
    db_json = json.dumps(db_dict)

    # encrypt with key and Fernet
    fernet = Fernet(key)
    db_crypt = fernet.encrypt(db_json)

    with file(filename, "wb") as f:
        f.write(salt)
        f.write(db_crypt)


def _load_db(password, filename):
    with file(filename, "rb") as f:
        salt = f.read(SALT_LEN)  # read salt
        if len(salt) != SALT_LEN:
            raise Exception("Corrupted/invalid db file. Failed to read salt")

        db_crypt = f.read()  # read full db

        # compute key
        key, salt = _gen_key(password, salt)
        fernet = Fernet(key)

        try:
            # decrypt
            db_json = fernet.decrypt(db_crypt)
        except Exception as e:
            # import traceback
            # traceback.print_exc(e)
            raise Exception("Decrypt failed. Check your password.")

    db_dict = json.loads(db_json)
    return db_dict


from cmd import Cmd


class CryptShell(Cmd):
    def do_open(self, args):
        """
        Open a db, load everything in memory.
        :param args: The db filename
        """
        args = args.split()
        self.options.db = args[0]
        self.prompt = "Crypt [] >>> "

        if not os.path.exists(self.options.db):
            print("Database file %s does not exist." % self.options.db)
            if self.do_create(args) is False:
                return False

        print("Opening database %s" % self.options.db)
        filename = self.options.db
        password = getpass.getpass("Password: ")
        db_dict = _load_db(password, filename)
        print("Opened db file %s, DB version string is \"%s\"" % (filename, db_dict["version"]))
        print("Created on %s" % db_dict["created"])
        print("Modified on %s" % db_dict["modified"])

        self.db_dict = db_dict
        self.password = password
        self.prompt = "Crypt [" + filename + "] >>> "
        return None

    def do_list(self, args):
        """
        List a key or keys to display. No arguments will print the entire db.
        :param key(s):
        """
        keys = args.split()

        if len(keys) == 0:
            keys = self.db_dict.keys()
        for k in keys:
            values = self.db_dict.get(k)
            if values is not None and type(values) is list:
                print("Key \"%s\"" % k)
                for v in values:
                    print("\t%s" % v)

        return None

    def do_generate(self, args):
        """
        Generate a random alphanumeric string of given length
        :param length: length of generated string
        """
        args = args.split()
        length = 32
        if len(args) > 0:
            length = int(args[0])

        chars = string.ascii_letters + string.digits + "!@#$%&"
        random.seed(os.urandom(1024))
        value = ''.join(random.choice(chars) for i in range(length))
        print("Generated value (length=%d): %s" % (length, value))
        return None 

    def do_append(self, args):
        """
        Append values to an existing key
        :param args: extra values
        """
        args = args.split()
        key = args[0]
        if self.db_dict.get(key) is None:
            print("Key \"%s\" does not exist. Use insert." % key)
            return False

        values = [str(v) for v in args[1:]]

        self.db_dict[key] += values
        _write_db(self.password, self.db_dict, self.options.db)
        print("Appended new values to existing list of key \"{}\" to db \"{}\"".format(key, self.options.db))
        return None

    def do_update(self, args):
        """
        Update the values of an existing key. Old values are deleted
        :param args: new values
        """
        args = args.split()
        key = args[0]
        if self.db_dict.get(key) is None:
            print("Key \"%s\" does not exist. Use insert." % key)
            return False

        values = [str(v) for v in args[1:]]
        if len(values) == 0:
            print("No values for key %s. This is pointless, i give up." % key)
            return False

        self.db_dict[key] = values
        _write_db(self.password, self.db_dict, self.options.db)
        print("Updated key \"{}\" to db \"{}\"".format(key, self.options.db))
        return None

    def do_password(self, args):
        """
        Change the password of the loaded database
        """
        if not os.path.exists(self.options.db) or self.db_dict is None or self.password is None:
            print("No database loaded. Aborting.")
            return False

        print("Changing password for database %s" % self.options.db)
        oldpassword = getpass.getpass("Enter old password: ")
        if oldpassword != self.password:
            print("Wrong password. Aborting.")

        password = getpass.getpass("Enter new password: ")
        password2 = getpass.getpass("Re-enter password: ")

        if password != password2:
            print("Passwords do not match.")
            return False

        self.password = password
        _write_db(self.password, self.db_dict, self.options.db)
        print("Password changed.")

    def do_create(self, args):
        """
        Create a new database. It will prompt for new password.
        The current db loaded is discarded. The file of the current db is not altered.

        :param filename: The filename for the new db
        """
        if type(args) is str:
            args = args.split()
            self.options.db = args[0]

        if os.path.exists(self.options.db):
            print("Database file %s already exists. Will not overwrite." % self.options.db)
            return False

        print("Creating database %s" % self.options.db)
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
        }

        print("Creating new db file %s" % (self.options.db,))
        _write_db(self.password, self.db_dict, self.options.db)
        return None

    def do_delete(self, args):
        """
        Delete a key (and its values).
        :param key: the key to delete
        """
        args = args.split()
        key = args[0]
        if self.db_dict.get(key) is None:
            print("Key \"%s\" does not exist.")
            return False

        self.db_dict.pop(key)
        _write_db(self.password, self.db_dict, self.options.db)
        print("Deleted key \"{}\" from db \"{}\"".format(key, self.options.db))
        return None

    def do_insert(self, args):
        """
        Insert a key and one or more values.
        :param key [value1] [value2] ...: key and values
        """
        args = args.split()
        key = args[0]
        if self.db_dict.get(key) is not None:
            print("Key \"%s\" already exists. Use update to overwrite" % key)
            return False

        values = [str(v) for v in args[1:]]

        if len(values) == 0:
            print("No values for key %s. This is pointless, i give up." % key)
            return False

        self.db_dict[key] = values
        _write_db(self.password, self.db_dict, self.options.db)
        print("Added new key \"{}\" to db \"{}\"".format(key, self.options.db))
        return None

    def do_quit(self, args):
        """Quit crypt."""
        raise SystemExit

    def do_clear(self, args):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _complete_key(self, text, line, beginidx, endidx):
        res = []
        if self.db_dict is not None:
            res = [s for s in self.db_dict.keys() if text in s]
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


if __name__ == '__main__':
    parser = create_parser()
    cl_opts, args = parser.parse_args()

    cshell = CryptShell()
    cshell.options = cl_opts

    try:
        res = cshell.do_open(cl_opts.db)
        if res is not False: # db opened succesfully
            cshell.cmdloop("Crypt shell " + VERSION)

    except Exception as e:
        print("Error: %s" % e.message)
        import traceback
        traceback.print_exc(e)
        exit(1)
