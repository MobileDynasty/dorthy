import redis
import time

from dorthy.settings import config
from dorthy.utils import native_str


client = redis.StrictRedis(host=config.redis.server,
                           port=config.redis.port,
                           db=config.redis.db)


def create_key(prefix, key, decode_key=False):
    """
    Creates a key

    :param prefix: the key prefix
    :param key: the key value
    :param decode_key: True if the key should be decoded into a native string
    :return: a new key
    """
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


def get_field(key, field, decode=False, pipe=client):
    """
    Gets a redis field given the key and the field

    :param key: a key
    :param field: a field name
    :param decode: True to decode the byte stream into a native string
    :param pipe: the pipe to use for the operation
    :return: the field value or None if it does not exist
    """
    redis_key = create_key(key, field)
    return native_str(pipe.get(redis_key)) if decode else pipe.get(redis_key)


def set_field(key, field, value, expire=None, pipe=client):
    """
    Sets a field value given the key and the field

    :param key: a key
    :param field: a field name
    :param value: the value to set
    :param expire: the number of seconds until the field expires or None
    :param pipe: the pipe to use for the operation
    """
    redis_key = create_key(key, field)
    pipe.set(redis_key, value, ex=expire)


def delete_field(key, field, pipe=client):
    """
    Deletes the field given the key and the field

    :param key: a key
    :param field: a field name
    :param pipe: the pipe to use for the operation
    :return the delete return code
    """
    redis_key = create_key(key, field)
    return pipe.delete(redis_key)


def exists_field(key, field, pipe=client):
    """
    Checks for existence of the field

    :param key: a key
    :param field: a field name
    :param pipe: the pipe to use for the operation
    :return: True if the field exists, otherwise False
    """
    redis_key = create_key(key, field)
    return pipe.exists(redis_key)


def incrby_field(key, field, amount=1, pipe=client):
    """
    Increments the given int field value by the amount

    :param key: a key
    :param field: a field name
    :param amount: the amount to increment by
    :param pipe: the pipe to use for the operation
    :return: the current value of the field
    """
    redis_key = create_key(key, field)
    return pipe.incrby(redis_key, amount=amount)

