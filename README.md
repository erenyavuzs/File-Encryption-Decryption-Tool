# File Encryption and Decryption Tool

This script allows you to encrypt and decrypt files using a specified key. The key is either generated automatically or provided by the user. Encryption is performed using the cryptography library.


### Setup
Install the required packages by running:
`pip install -r requirements.txt`


### Usage
To see the available options and usage of the script, run:
`python crypt.py --help`

/br
/br
/br


## Encrypting and Decrypting Files

### Generate a New Key and Encrypt a File
To encrypt data.csv using a newly generated key:
`python crypt_1.py data.csv --generate-key --encrypt`


This command will:
Generate a new encryption key and save it to key.key.
Encrypt data.csv using this new key.

### 




