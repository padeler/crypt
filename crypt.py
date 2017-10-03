"""crypt

Usage:
    crypt.py create [--db=filename.db]
    crypt.py insert [--db=filename.db] [-g] <key> [<id=val>|val]...
    crypt.py update [--db=filename.db] <key> [<id=val>|val]...
    crypt.py append [--db=filename.db] <key> [<id=val>|val]...
    crypt.py delete [--db=filename.db] <key>
    crypt.py select [--db=filename.db] [<key>|all]

Options:
 -h, --help  show this
 -d filename.db | --db=filename.db   database file name. If omitted, default is crypt.db
 -g          generate random alphanumeric string as value

"""
from optparse import OptionParser
import os
import getpass
import datetime
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



VERSION = "crypt v0.1"
SALT_LEN = 16


def create_parser():
    parser = OptionParser("usage: %prog <create|insert|update|append|delete|select> [options] values...")
    parser.add_option("-d", "--db", metavar="file.db", help="Database file. Default is crypt.db", default="crypt.db")
    parser.add_option("-g", action="store_true", dest="generate_value", help="Auto-generate value", default=False)
    return parser



def _gen_key(password, salt = os.urandom(SALT_LEN)):
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),
                     length = 32,
                     salt = salt,
                     iterations = 100000,
                     backend = default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # with file(options.db, 'w') as f:
    print "Key: ", len(key), key
    print "SALT: ", len(salt), salt

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
        salt = f.read(SALT_LEN) # read salt
        if len(salt) != SALT_LEN:
            raise Exception("Corrupted/invalid db file. Failed to read salt")

        db_crypt = f.read() # read db


        # compute key
        key, salt = _gen_key(password, salt)
        fernet = Fernet(key)

        # decrypt
        db_json = fernet.decrypt()
        db_dict = json.loads(db_json)

    return db_dict



def _open(filename):
    password = getpass.getpass("Password:")
    db_dict = _load_db(password, filename)
    return db_dict


def create(args, options):
    if os.path.isfile(options.db):
        raise Exception("Db file already exists. Will not overwrite.")

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

    print("Creating new db file %s on %s" % (options.db, ts))

    _write_db(password, db_dict, options.db)


    pass

def delete(args, options):
    pass

def insert(args, options):
    pass


def update(args, options):
    pass


def append(args, options):
    pass


def select(args, options):
    db_dict = _open(options.db)
    print "DB: \n", db_dict

    pass


commands = {"create": create,
            "insert": insert,
            "select": select,
            }

if __name__ == '__main__':
    parser = create_parser()
    options, args = parser.parse_args()
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
        print("Command Error: ", e.message)
        parser.print_help()
        exit(2)

