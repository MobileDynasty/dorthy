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


def encrypt_password(password, encryption_algorithm=PasswordEncryptionAlgorithms.BCrypt):

    assert password, "Password cannot be None"

    if encryption_algorithm == PasswordEncryptionAlgorithms.BCrypt:
        return bcrypt.hashpw(password, bcrypt.gensalt()) if password else None
    else:
        raise NotImplementedError()


def validate_password(password, token, encryption_algorithm=PasswordEncryptionAlgorithms.BCrypt):
    if encryption_algorithm == PasswordEncryptionAlgorithms.BCrypt:
        return bcrypt.hashpw(password, token) == token
    else:
        raise NotImplementedError()


class SecureHashAlgorithms(DeclarativeEnum):

    SHA1 = "1",
    SHA2 = "2"


def secure_hash(data, hash_algorithm=SecureHashAlgorithms.SHA2):
    b = data.encode("utf-8") if isinstance(data, str) else data
    if hash_algorithm == SecureHashAlgorithms.SHA1:
        m = hashlib.sha1()
        m.update(b)
        return codecs.encode(m.digest(), "hex_codec").decode("utf-8")
    elif hash_algorithm == SecureHashAlgorithms.SHA2:
        m = hashlib.sha256()
        m.update(b)
        return codecs.encode(m.digest(), "hex_codec").decode("utf-8")
    else:
        raise NotImplementedError()


def secure_salted_hash(data, hash_algorithm=SecureHashAlgorithms.SHA2, salt=None):
    if not salt:
        salt = generate_id(chars=string.ascii_lowercase + string.digits, size=12)
    return secure_hash(data + salt, hash_algorithm=hash_algorithm), salt


def valid_hash(stored_hash, token, hash_algorithm=SecureHashAlgorithms.SHA2):
    if hash_algorithm == SecureHashAlgorithms.SHA1:
        h = stored_hash[0:40]
        if len(stored_hash) > 40:
            # contains a salt
            salt = stored_hash[40:]
            token += salt
        return secure_hash(token, hash_algorithm=SecureHashAlgorithms.SHA1) == h
    elif hash_algorithm == SecureHashAlgorithms.SHA2:
        h = stored_hash[0:64]
        if len(stored_hash) > 64:
            # contains a salt
            salt = stored_hash[64:]
            token += salt
        return secure_hash(token, hash_algorithm=SecureHashAlgorithms.SHA2) == h
    else:
        raise NotImplementedError()

