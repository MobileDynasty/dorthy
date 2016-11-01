from cachetools import LRUCache, TTLCache

from dogpile.cache import register_backend
from dogpile.cache.api import CacheBackend, NO_VALUE

from dorthy.security import crypto


def sha2_mangle_key(key):
    return crypto.secure_hash(key, crypto.SecureHashAlgorithms.SHA2)


class LRULocalBackend(CacheBackend):

    def __init__(self, arguments):
        maxsize = arguments.get("maxsize", 1024)
        ttl = arguments.get("ttl", None)
        if ttl:
            self.__cache = TTLCache(maxsize, ttl=ttl)
        else:
            self.__cache = LRUCache(maxsize)

    def get(self, key):
        return self.__cache.get(key, NO_VALUE)

    def set(self, key, value):
        self.__cache[key] = value

    def delete(self, key):
        del self.__cache[key]


register_backend("dorthy.cache.local.lru", "dorthy.cache", "LRULocalBackend")
