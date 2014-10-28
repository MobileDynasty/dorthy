import base64
import logging
import pickle
import sys

from collections import MutableMapping
from time import time
from uuid import uuid4

from tornado.escape import json_decode

from dorthy.json import jsonify

logger = logging.getLogger(__name__)

DEFAULT_SESSION_TIMEOUT = 86400 * 1


class Session(MutableMapping):
    """Provides a session data structure that provides dictionary
    access.  Provides JSON serialization and deserialization methods.
    """

    _SYS_ENCODING = sys.getdefaultencoding()

    def __init__(self, session_id, timeout=DEFAULT_SESSION_TIMEOUT, update_access=True):
        self.__session_id = session_id
        self.__created = time()
        self.__last_accessed = self.__created
        self.__new = True
        self.__modified = False
        self.__valid = True
        self.__data = dict()
        self.timeout = timeout
        self.update_access = update_access

    def __contains__(self, key):
        return key in self.__data

    def __len__(self):
        return len(self.__data)

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value
        self.__modified = True

    def __delitem__(self, key):
        del self.__data[key]
        self.__modified = True

    def __iter__(self):
        return iter(self.__data)

    def clear(self):
        self.__data.clear()
        self.__modified = True

    def pop(self, key, *args):
        self.__modified = self.__modified or key in self.__data
        return self.__data.pop(key, *args)

    @property
    def created(self):
        return self.__created

    @property
    def session_id(self):
        return self.__session_id

    @property
    def data(self):
        return dict(self.__data)

    def expired(self):
        if self.timeout <= 0:
            expired = False
        elif self.last_accessed == 0:
            expired = self.created + self.timeout < time()
        else:
            expired = self.last_accessed + self.timeout < time()
        return expired

    @property
    def last_accessed(self):
        return self.__last_accessed

    def _update_accessed(self):
        if self.update_access:
            self.__last_accessed = time()

    @property
    def modified(self):
        return self.__modified

    @property
    def is_new(self):
        return self.__new

    @property
    def valid(self):
        return self.__valid

    def encode(self):
        d = self._as_dict()
        # pickle data elements
        if d["data"]:
            pickled = pickle.dumps(self.__data)
            d["data"] = base64.standard_b64encode(pickled).decode(self._SYS_ENCODING)
        return jsonify(d)

    def _as_dict(self):
        d = dict()
        d["session_id"] = self.__session_id
        d["created"] = self.__created
        d["last_accessed"] = self.__last_accessed
        d["timeout"] = self.timeout
        d["update_access"] = self.update_access
        d["data"] = self.__data
        return d

    @classmethod
    def decode(cls, data):
        d = json_decode(data)
        self = cls.__new__(cls)
        self.__session_id = d["session_id"]
        self.__created = d["created"]
        self.__last_accessed = d["last_accessed"]
        self.__new = False
        self.__modified = False
        self.timeout = d["timeout"]
        if not self.timeout:
            self.timeout = DEFAULT_SESSION_TIMEOUT
        self.update_access = d["update_access"]
        self.__valid = True
        if "data" not in d:
            self.__data = dict()
        elif d["data"]:
            data = d["data"]
            # decode pickled data
            b = data.encode(self._SYS_ENCODING)
            pickled = base64.standard_b64decode(b)
            self.__data = pickle.loads(pickled)
        return self

    def invalidate(self):
        self.__valid = False
        self.__modified = True


class BaseSessionStore(object):

    @staticmethod
    def generate_session_id():
        return uuid4().hex

    def load(self, session_id):
        pass

    def save(self, session):
        if not session.valid:
            self._delete(session.session_id)
        else:
            self._store_session(session)

    def _delete(self, session_id):
        pass

    def _store_session(self, session):
        pass

    def _validate_session(self, session):
        if session and session.expired():
            self._delete(session.session_id)
            session = None
        return session


class InMemorySessionStore(BaseSessionStore):

    def __init__(self):
        self.__store = dict()

    def load(self, session_id):
        return self._validate_session(self.__store.get(session_id, None))

    def _delete(self, session_id):
        del self.__store[session_id]

    def _store_session(self, session):
        if session.valid:
            session._update_accessed()
            self.__store[session.session_id] = session
        else:
            self._delete(session.session_id)
