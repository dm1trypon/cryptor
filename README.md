# CryptorFiles

App on Python 3.6. Encrypt and decrypt files.

## Dependencies:

1. Crypto   
2. argparse   
3. os   

## Project structure:

1. 'generate_key.py' - Generates public and private encryption keys.   
2. 'encrypt_files.py' - Encrypts files with a public key.   
3. 'decrypt_files.py' - Decrypts files with a private key.   

## Run:

First of all, run generate_key.py, generate two keys, then encrypt_files.py, decrypt_files.py to decrypt.

## Example:

`python3 generate_key.py -pw password`   
`python3 encrypt_files.py -p /home/user/folder/ --hack`   
`python3 decrypt_files.py -p /home/user/folder/ -pw password --clean`   

## Arguments:

`--hack` - remove source files when encrypt process start.   
`--clean` - like a `--hack`, but when decrypting is started.   
`-p` - path to directory.   
`-f` - path to file.   
`-pw` - password encrypting.   