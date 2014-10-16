import redis
import time

from dorthy.settings import config
from dorthy.utils import native_str


client = redis.StrictRedis(host=config.redis.server,
                           port=config.redis.port,
                           db=config.redis.db)


def create_key(prefix, key, decode_key=False):
    key = key if not decode_key else native_str(key)
    return "{}:{}".format(prefix, key)


def get_cached_value(key, ttl):
    """
    Gets a cached value and determines whether or not it has expired
    according to its time to live (ttl)

    Args:
        key: key under which data is stored
        ttl: time to live for key (in seconds)
    Returns:
        (cached_value, expired)
    """
    cached_value = client.hget(key, 'data')
    timestamp = client.hget(key, 'ts')

    if timestamp and time.time() - float(timestamp) > ttl:
        expired = True
    else:
        expired = False
    return cached_value, expired


def cache_value(key, value):
    """
    Caches a value along with current timestamp

    Args:
        key: key under which data is stored
        value: str or number value ready to be stored
    Returns:
        Redis return value
    """
    assert isinstance(value, (str, int, float, complex))
    return client.hmset(key, {'data': value, 'ts': time.time()})