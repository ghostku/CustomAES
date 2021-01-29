#
# Encryption with AES-CBC
# Adapted to work with CryptoJS (crypto-js@3.1.9) with default configuration
#
# Python 2.7.13
# pkcs7==0.1.0
# pycrypto==2.6.1
#
import binascii
import struct
import hashlib

from settings import KEY, MESSAGE, JS_TRANSFORMED_KEY, JS_SALT, JS_KEY, JS_IV
from check import compare

from pkcs7 import PKCS7Encoder
from Crypto.Cipher import AES  #upm package(pycryptodome)
from Crypto import Random  #upm package(pycrypto)

from custom_aes import CustomAES

MODE = AES.MODE_CBC


def evpKDF(passwd,
           salt,
           key_size=8,
           iv_size=4,
           iterations=1,
           hash_algorithm="md5"):
    """
    https://github.com/Shani-08/ShaniXBMCWork2/blob/master/plugin.video.serialzone/jscrypto.py
    """
    target_key_size = key_size + iv_size
    derived_bytes = ""
    number_of_derived_words = 0
    block = None
    hasher = hashlib.new(hash_algorithm)
    while number_of_derived_words < target_key_size:
        if block is not None:
            hasher.update(block)

        hasher.update(passwd)
        hasher.update(salt)
        block = hasher.digest()
        hasher = hashlib.new(hash_algorithm)

        for i in range(1, iterations):
            hasher.update(block)
            block = hasher.digest()
            hasher = hashlib.new(hash_algorithm)

        derived_bytes += block[0:min(
            len(block), (target_key_size - number_of_derived_words) * 4)]
        number_of_derived_words += len(block) / 4

    return {
        "key": derived_bytes[0:key_size * 4],
        "iv": derived_bytes[key_size * 4:]
    }


def decrypt(passphrase, encrypted_text):
    encrypted_text_bytes = binascii.a2b_base64(encrypted_text)
    # print("Original encrypted message = %s" % binascii.b2a_hex(encrypted_text_bytes))

    # Remove "Salt__"
    encrypted_text_bytes = encrypted_text_bytes[8:]

    # Get and remove SALT
    salt = encrypted_text_bytes[:8]
    encrypted_text_bytes = encrypted_text_bytes[8:]
    # print("encrypted_text_bytes = %s" % binascii.b2a_hex(encrypted_text_bytes))
    compare(binascii.b2a_hex(salt), JS_SALT, ' SALT')

    # Get KEY and IV
    resp = evpKDF(passphrase, salt, key_size=32, iterations=10000)
    key = resp.get("key")
    iv = resp.get('iv')

    compare(binascii.b2a_hex(key), JS_KEY, 'KEY')
    compare(binascii.b2a_hex(iv), JS_IV, 'IV')



    # aes = AES.new(key, MODE, iv)
    # decrypted_text = aes.decrypt(encrypted_text_bytes)
    # encoder = PKCS7Encoder()
    # unpad_text = encoder.decode(decrypted_text)
    # print("unpad_text = %s" % binascii.b2a_hex(unpad_text))

    return unpad_text


def transform_key(key):
    i = hashlib.sha512(key.encode('utf-8'))
    for n in range(11512):
        i = hashlib.sha512(i.digest())
    key = i.hexdigest()
    return key


if __name__ == '__main__':

    TRANSFORMED_KEY = transform_key(KEY)
    if not compare(TRANSFORMED_KEY, JS_TRANSFORMED_KEY, 'Transformed KEY'):
        exit(1)

    # exit(1)
    # encrypted_text = encrypt(KEY, PLAINTEXT)
    # print("encrypted_text (base64)= %s" % encrypted_text)

    print("\n\nDECRYPT")
    decrypted_text = decrypt(TRANSFORMED_KEY, MESSAGE)
    # print("decrypted text = %s" % decrypted_text)
