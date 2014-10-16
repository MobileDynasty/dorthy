import base64
import bcrypt
import codecs
import hashlib
import hmac
import string
import sys

from functools import partial
from hashlib import sha1

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

from dorthy.enum import DeclarativeEnum
from dorthy.settings import config


def generate_id(chars=string.ascii_uppercase + string.digits, size=8):
    return ''.join(random.choice(chars) for x in range(size))


def sign_message(key, msg, digest=sha1):
    hashed = hmac.new(key, msg, digest)
    return base64.b64encode(hashed.digest())


def aes_encrypt(key, text, base64_encode=True, encoding=None):
    """
    Provides an AES encryption routine using cipher feedback
    block algorithm

    :rtype : encrypted bytes
    """
    assert key is not None

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    # encode string into bytes
    if not encoding:
        encoding = sys.getdefaultencoding()
    value = iv + cipher.encrypt(text.encode(encoding))
    if base64_encode:
        value = base64.b64encode(value).decode(encoding)
    return value


def aes_decrypt(key, cipher_text, base64_encode=True, encoding=None):
    """
    Provides an AES decryption routine using cipher feedback
    block algorithm

    :type key: the decrypted text
    """
    assert key is not None

    iv = cipher_text[0:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    if not encoding:
        encoding = sys.getdefaultencoding()
    if isinstance(cipher_text, str):
        # encode into bytes
        cipher_text = cipher_text.encode(encoding)
    if base64_encode:
        cipher_text = base64.b64decode(cipher_text)
    text = cipher.decrypt(cipher_text)
    return text[AES.block_size:].decode(encoding)


if "security.encryption_key" in config:
    private_key = config.security.encryption_key.encode(sys.getdefaultencoding())
else:
    private_key = None

encrypt = partial(aes_encrypt, private_key)
decrypt = partial(aes_decrypt, private_key)


class PasswordEncryptionAlgorithms(DeclarativeEnum):

    BCrypt = "1",
    SHA1 = "2",


def encrypt_password(password, encryption_algorithm=PasswordEncryptionAlgorithms.BCrypt):

    assert password, "Password cannot be None"

    if encryption_algorithm == PasswordEncryptionAlgorithms.BCrypt:
        return bcrypt.hashpw(password, bcrypt.gensalt()) if password else None
    elif encryption_algorithm == PasswordEncryptionAlgorithms.SHA1:
        m = hashlib.sha1()
        m.update(password.encode('utf-8'))
        return codecs.encode(m.digest(), 'hex_codec').decode("utf-8")
    else:
        raise NotImplemented


def validate_password(password, token, encryption_algorithm=PasswordEncryptionAlgorithms.BCrypt):
    if encryption_algorithm == PasswordEncryptionAlgorithms.BCrypt:
        return bcrypt.hashpw(password, token) == token
    else:
        raise NotImplemented
