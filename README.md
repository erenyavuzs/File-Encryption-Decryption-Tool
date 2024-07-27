# File Encryption and Decryption Tool

This script allows you to encrypt and decrypt files using a specified key. The key is either generated automatically or provided by the user. Encryption is performed using the cryptography library.


### Setup
Install the required packages by running:
`pip install -r requirements.txt`


### Usage
To see the available options and usage of the script, run:
`python crypt_1.py --help`

<br>
<br>
<br>


## Encrypting and Decrypting Files

### Generate a New Key and Encrypt a File
To encrypt data.csv using a newly generated key:
`python crypt_1.py data.csv --generate-key --encrypt`


This command will:
Generate a new encryption key and save it to `key.key`.
Encrypt `data.csv` using this new key.


### To use with the existing key
`python crypt_1.py data.csv --encrypt`


### Decrypt a File
To decrypt the file (make sure to use the same key that was used for encryption):
`python crypt.py data.csv --decrypt`

## Encrypt Another File Using the Same Key
To encrypt another file using the previously generated key:
`python crypt.py another_file --encrypt`

<br>
<br>

## Additional Notes
Ensure that (key.key) is kept secure and accessible for future decryption operations.
Ensure the key file (key.key) is in the same directory as the script and is not modified.










