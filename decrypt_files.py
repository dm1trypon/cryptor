import argparse
import os

from os.path import basename
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

PRIVATE_KEY = "private_key.bin"
PATH = "path"
FILE = "file"

def decrypto_file(file_name, arg_password, clean_mode):
    print('Source file: ', file_name, "--> ", file_name[:-4])
    with open(file_name, 'rb') as fobj:
        private_key = RSA.import_key(
            open(PRIVATE_KEY).read(),
            passphrase=arg_password)

        enc_session_key, nonce, tag, ciphertext = [
            fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]
        fobj.close()
        if (clean_mode == 1):
            os.remove(file_name)
            
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        
        create_decrypt_file(cipher_aes.decrypt_and_verify(ciphertext, tag), file_name)

def create_decrypt_file(data, file_name):
    file_decrypt = open(file_name[:-4], "wb")
    file_decrypt.write(data)
    file_decrypt.close()

def list_files_path(path_folder):
    list_files = []
    for top, dirs, files in os.walk(path_folder):
        for nm in files:       
            list_files.append(os.path.join(top, nm))
            
    return list_files

def crypto_operation(type, arg_parse, arg_password, clean_mode):
    if (type == PATH):
        for file in list_files_path(arg_parse):
            decrypto_file(file, arg_password, clean_mode)

    if (type == FILE):
        decrypto_file(arg_parse, arg_password, clean_mode)

def args_parser(args):
    if (args.clean):
        clean_mode = 1
    else:
        clean_mode = 0

    if ((not args.p) and (not args.f) and (not args.pw)):
        print("Args is empty, try --help.")

    if args.p:
        crypto_operation(PATH, args.p, args.pw, clean_mode)

    if args.f:
        crypto_operation(FILE, args.f, args.pw, clean_mode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is app for crypt files.')
    parser.add_argument('-p', type=str, help='Path to folder with files.')
    parser.add_argument('-f', type=str, help='Path to file.')
    parser.add_argument('-pw', type=str, help='Password to decrypt files.')
    parser.add_argument('--clean', action='store_true', help='Delete sources encryptions files.')
    args_parser(parser.parse_args())