import argparse

from Crypto.PublicKey import RSA

PRIVATE_KEY = "private_key.bin"
PUBLIC_KEY = "public_key.pem"
PROTECTION = "scryptAndAES128-CBC"
PKCS = 8

def set_encryption_key(password):
    key = RSA.generate(2048)

    encrypted_key = key.exportKey(
        passphrase=password,
        pkcs=PKCS,
        protection=PROTECTION)

    try:
        create_private_key(encrypted_key)
        create_public_key(encrypted_key, key)
    except:
        print("Cannot create key's file, aborted.")

def create_private_key(encrypted_key):
    with open(PRIVATE_KEY, 'wb') as f:
        f.write(encrypted_key)
 
def create_public_key(encrypted_key, key):
    with open(PUBLIC_KEY, 'wb') as f:
        f.write(key.publickey().exportKey())

def args_parser(args):
    if not args.pw:
        print("Args is empty, try --help.")
    else:
        set_encryption_key(args.pw)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is app for crypt files.')
    parser.add_argument('-pw', type=str, help='Password for private key.')
    args_parser(parser.parse_args())