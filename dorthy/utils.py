from collections import Iterable
from pytz import timezone, utc

import datetime
import email.utils
import json
import inspect
import re
import time

from .dp import ObjectDict


def native_str(x, encoding="utf-8", errors="ignore", default=None):
    if x:
        return x if isinstance(x, str) else x.decode(encoding, errors)
    else:
        return default


def now(tz_str="utc"):
    return datetime.datetime.now(timezone(tz_str))


def convert_from_utc(dt, tz_str):
    return dt.replace(tzinfo=utc).astimezone(timezone(tz_str))


def rfc_2822_timestamp(dt=None):
    if not dt:
        dt = datetime.datetime.now()
    return email.utils.formatdate(time.mktime(dt.timetuple()))


def convert_from_rfc_2822(timestamp):
    return datetime.datetime.fromtimestamp(email.utils.mktime_tz(email.utils.parsedate_tz(timestamp)), utc)


def int_parse(x, default=None):
    if not x:
        return x
    try:
        return int(x)
    except ValueError:
        return default


def is_int(x):
    return int_parse(x, default=None) is not None


def trunc(s, length=-1, strip=True, ellipsis=False, convert_to_none=True):
    """
    Truncates a string to the given length. If strip is
    true then also strips the string.  If ellipsis is true then
    ellipsis are added to the end of the string.
    """
    if not s:
        if convert_to_none and s is not None:
            return None
        return s
    if strip:
        s = s.strip()
        if convert_to_none and not s:
            return None
    if length > 0:
        if ellipsis:
            length -= 3
            return (s[:length] + "...") if len(s) > length else s
        else:
            return s[:length]
    else:
        return s


def xstr(s):
    """
    Returns the given object as a string or if None then
    returns the empty string
    """
    return str(s) if s else ""


def combine_bytes(*args, separator=None):
    count = len(args)
    b = bytearray()
    for indx, val in enumerate(args):
        b += val
        if separator and indx + 1 < count:
            b += separator
    return b


def unique(l):
    """Returns a new list with all the unique elements in l"""
    return list(set(l))


def intersect(a, b):
    """Returns a new list of the intersection of a and b"""
    return set(a) & set(b)


def union(a, b):
    """Returns a new list of the union between a and b"""
    return set(a) | set(b)


def diff(a, b):
    """Returns a new list of the differences between a and b"""
    return set(b).difference(set(a))


def create_frozenset(obj):
    if not obj:
        return frozenset()
    if not isinstance(obj, str) and isinstance(obj, Iterable):
        return frozenset(obj)
    else:
        return frozenset([obj])


def create_list(obj):
    if not obj:
        return list()
    if not isinstance(obj, str) and isinstance(obj, Iterable):
        return list(obj)
    else:
        return [obj]


def create_set(obj):
    if not obj:
        return set()
    if not isinstance(obj, str) and isinstance(obj, Iterable):
        return set(obj)
    else:
        return {obj}


def hasmethod(obj, name):
    if hasattr(obj, name):
        method = getattr(obj, name)
        return inspect.ismethod(method)
    return False


def hasfunc(obj, name):
    if hasattr(obj, name):
        func = getattr(obj, name)
        return inspect.isfunction(func)
    return False


_REPLACE_UNDERSCORE = re.compile("_([a-z])")


def camel_match(match):
    return match.group(0)[1:].upper()


def camel_encode(s):
    return re.sub(_REPLACE_UNDERSCORE, camel_match, s)


_FIRST_CAP = re.compile("(.)([A-Z][a-z]+)")
_ALL_CAP = re.compile("([a-z0-9])([A-Z])")


def camel_decode(s):
    return _ALL_CAP.sub(r"\1_\2", _FIRST_CAP.sub(r"\1_\2", s)).lower()


class Switch(object):

    def __init__(self, s_map):
        self.__s_map = s_map

    def switch(self, case, *args, **kwargs):
        f = self.__s_map.get(case, None)
        if f is None:
            # use default
            f = self.__s_map.get("default", None)
            if f is None:
                raise NotImplementedError("No default case found for case: " + xstr(case))
        f(*args, **kwargs)


def _process_camel_case(d):
    processed = dict()
    for key, value in d.items():
        processed[camel_decode(key)] = value
    return processed


def parse_json(s, underscore_case=True, object_dict_wrapper=True):
    if underscore_case:
        json_dict = json.loads(s, object_hook=_process_camel_case)
    else:
        json_dict = json.loads(s)
    return ObjectDict(json_dict) if object_dict_wrapper else json_dict

