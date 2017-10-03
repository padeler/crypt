#!/usr/bin/python

"""crypt

Create, view and maintain a hashtable db.
The hashtable dumped to a json string and is stored encrypted.

Encryption/decryption is done using the Fernet symmetric encryption spec.
https://github.com/fernet/spec/blob/master/Spec.md

Depends on the "cryptography" python package.

Usage:
    crypt.py create [-d filename.db]
    crypt.py insert [-d filename.db] [-g len] key [values...]
    crypt.py update [-d filename.db] [-g len] key [values...]
    crypt.py append [-d filename.db] [-g len] key [values...]
    crypt.py delete [-d filename.db] key
    crypt.py select [-d filename.db] [key...]

Options:
 -h, --help  show this
 -d filename.db | --db=filename.db   database file name. If omitted, default is crypt.db
 -g          generate random alphanumeric string as value

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
    parser = OptionParser("usage: %prog <create|insert|update|append|delete|select> [options] values...")
    parser.add_option("-d", dest="db", metavar="file.db", help="Database file. Default is crypt.db", default="crypt.db")
    parser.add_option("-g", metavar="length", type="int", dest="generate_value", help="Auto-generate value of given length")
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


def _open(filename):
    if not os.path.isfile(options.db):
        raise Exception("Database file %s does not exist." % options.db)

    password = getpass.getpass("Password:")
    db_dict = _load_db(password, filename)
    print("Opened db file %s version %s" % (filename, db_dict["version"]))
    print("Created on %s" % db_dict["created"])
    print("Modified on %s" % db_dict["modified"])

    return db_dict, password


def create(args, options):
    if os.path.isfile(options.db):
        raise Exception("Database file %s already exists. Will not overwrite." % options.db)

    password = getpass.getpass("Enter new password:")
    password2 = getpass.getpass("Re-enter password:")

    if password != password2:
        print("Passwords do not match.")
        return

    ts = datetime.datetime.now()
    db_dict = {
        "created": str(ts),
        "version": VERSION,
    }

    print("Creating new db file %s" % (options.db,))
    _write_db(password, db_dict, options.db)
    pass


def delete(args, options):
    db_dict, password = _open(options.db)
    key = args[0]
    if db_dict.get(key) is None:
        raise Exception("Key \"%s\" does not exist.")

    db_dict.pop(key)
    _write_db(password, db_dict, options.db)
    print("Deleted key \"{}\" from db \"{}\"".format(key, options.db))
    pass


def _generate_value(length=20):
    chars = string.ascii_letters + string.digits + "!@#$%&"
    random.seed(os.urandom(1024))
    value = ''.join(random.choice(chars) for i in range(length))
    print("Generated value (length=%d): %s" % (length, value))
    return value


def insert(args, options):
    db_dict, password = _open(options.db)
    key = args[0]
    if db_dict.get(key) is not None:
        raise Exception("Key \"%s\" already exists. Use update to overwrite" % key)

    values = []
    if options.generate_value:
        values.append(_generate_value(options.generate_value))

    values += [str(v) for v in args[1:]]

    if len(values)==0:
        raise Exception("No values for key %s. This is pointless, i give up." % key)

    db_dict[key] = values
    _write_db(password, db_dict, options.db)
    print("Added new key \"{}\" to db \"{}\"".format(key, options.db))


def update(args, options):
    db_dict, password = _open(options.db)
    key = args[0]
    if db_dict.get(key) is None:
        raise Exception("Key \"%s\" does not exist. Use insert." % key)

    values = []
    if options.generate_value:
        values.append(_generate_value(options.generate_value))

    values += [str(v) for v in args[1:]]
    if len(values)==0:
        raise Exception("No values for key %s. This is pointless, i give up." % key)

    db_dict[key] = values
    _write_db(password, db_dict, options.db)
    print("Updated key \"{}\" to db \"{}\"".format(key, options.db))


def append(args, options):
    db_dict, password = _open(options.db)
    key = args[0]
    if db_dict.get(key) is None:
        raise Exception("Key \"%s\" does not exist. Use insert." % key)

    values = []
    if options.generate_value:
        values.append(_generate_value(options.generate_value))

    values += [str(v) for v in args[1:]]

    db_dict[key] += values
    _write_db(password, db_dict, options.db)
    print("Appended new values to existing list of key \"{}\" to db \"{}\"".format(key, options.db))


def select(args, options):
    db_dict, password = _open(options.db)
    keys = args
    if len(keys) == 0:
        keys = db_dict.keys()
    for k in keys:
        values = db_dict.get(k)
        if values is not None and type(values) is list:
            print("Key \"%s\"" % k)
            for v in values:
                print("\t%s" % v)


commands = {"create": create,
            "insert": insert,
            "select": select,
            "update": update,
            "append": append,
            "delete": delete,
            }

if __name__ == '__main__':
    parser = create_parser()
    options, args = parser.parse_args()
    if len(args) == 0:
        parser.print_help()
        exit(0)

    # print "Options: ", options
    # print "Args: ", args

    cmd = commands.get(args[0])

    if cmd is None:
        print("Invalid command.")
        parser.print_help()
        exit(1)

    try:
        cmd(args[1:], options)
    except Exception as e:
        print("Error: %s" % e.message)
        # import traceback
        # traceback.print_exc(e)
        exit(2)
