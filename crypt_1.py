import argparse
import base64
import getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets

def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = load_salt()
    elif save_salt:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
        with open(filename, "wb") as file:
            file.write(decrypted_data)
        print("File successfully decrypted.")
    except cryptography.fernet.InvalidToken:
        print("Decryption error: The key or file might be invalid.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Encryptor Script")
    parser.add_argument("file", help="File to encrypt/decrypt")
    parser.add_argument("-g", "--generate-key", action="store_true",
                        help="Generate a new key (creates a key.key file)")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt the file")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Decrypt the file")

    args = parser.parse_args()
    file = args.file

    if args.generate_key:
        write_key()
        print("New key created and saved to key.key.")
        exit()

    if args.encrypt or args.decrypt:
        key = load_key()

        if args.encrypt and args.decrypt:
            raise ValueError("Please specify only one action: encryption (-e) or decryption (-d).")
        elif args.encrypt:
            encrypt(file, key)
            print(f"{file} successfully encrypted.")
        elif args.decrypt:
            decrypt(file, key)
    else:
        raise ValueError("Please specify an action: encryption (-e) or decryption (-d).")
