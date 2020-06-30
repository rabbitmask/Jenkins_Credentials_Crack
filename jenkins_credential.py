#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
'''
 ____       _     _     _ _   __  __           _
|  _ \ __ _| |__ | |__ (_) |_|  \/  | __ _ ___| | __
| |_) / _` | '_ \| '_ \| | __| |\/| |/ _` / __| |/ /
|  _ < (_| | |_) | |_) | | |_| |  | | (_| \__ \   <
|_| \_\__,_|_.__/|_.__/|_|\__|_|  |_|\__,_|___/_|\_\
'''
import re
import sys
import base64
from hashlib import sha256
from Crypto.Cipher import AES

MAGIC = b"::::MAGIC::::"

def usage():
  print("python3 jenkins_credential.py <master.key> <hudson.util.Secret> <secretPassphrase>")
  sys.exit(0)

def decryptNewPassword(secret, p):
    p = p[1:]

    iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)
    p = p[4:][4:]
    iv = p[:iv_length]
    p = p[iv_length:]
    o = AES.new(secret, AES.MODE_CBC, iv)
    decrypted_p = o.decrypt(p)
    fully_decrypted_blocks = decrypted_p[:-16]
    possibly_padded_block = decrypted_p[-16:]
    padding_length = possibly_padded_block[-1]
    if padding_length <= 16:
        possibly_padded_block = possibly_padded_block[:-padding_length]

    pw = fully_decrypted_blocks + possibly_padded_block
    pw = pw.decode('utf-8')
    return pw

def decryptOldPassword(secret, p):
    o = AES.new(secret, AES.MODE_ECB)
    x = o.decrypt(p)
    assert MAGIC in x
    return re.findall('(.*)' + MAGIC, x)[0]

def main():
    if len(sys.argv) != 4:
        usage()

    master_key = open(sys.argv[1], 'rb').read()
    hudson_secret_key = open(sys.argv[2], 'rb').read()
    hashed_master_key = sha256(master_key).digest()[:16]
    o = AES.new(hashed_master_key, AES.MODE_ECB)
    secret = o.decrypt(hudson_secret_key)

    secret = secret[:-16]
    secret = secret[:16]

    password=sys.argv[3]
    p = base64.decodebytes(bytes(password, 'utf-8'))

    payload_version = p[0]
    if payload_version == 1:
      print(decryptNewPassword(secret, p))
    else:
      print(decryptOldPassword(secret,p))

if __name__ == '__main__':
    main()
