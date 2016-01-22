import functools
import logging
import threading
from collections import MutableMapping
from contextlib import contextmanager

from tornado.stack_context import StackContext

from dorthy.dp import Observable


logger = logging.getLogger(__name__)


class RequestContextError(Exception):
    pass


class RequestLocalStore(threading.local):

    def __init__(self):
        super().__init__()
        self.__context = None

    @property
    def active(self):
        return True if self.__context is not None else False

    @property
    def context(self):
        return self.__context

    @context.setter
    def context(self, context):
        assert not self.active
        self.__context = context

    def release(self):
        self.__context = None

_request_store = RequestLocalStore()


class RequestContext(MutableMapping):

    def __init__(self, values=None, immutables=None):
        self.__active = False
        self.__store = dict() if values is None else values.copy()
        self.__immutables = set() if immutables is None else immutables.copy()
        self.__observable = Observable()

    def __contains__(self, item):
        return item in self.__store

    def __len__(self):
        return len(self.__store)

    def __getitem__(self, item):
        return self.__store[item]

    def __delitem__(self, key):
        self.__check_immutable(key)
        del self.__store[key]

    def __setitem__(self, key, value):
        self.__check_immutable(key)
        self.__store[key] = value

    def __iter__(self):
        return iter(self.__store)

    @property
    def active(self):
        return self.__active

    @property
    def id(self):
        return id(self)

    def __check_immutable(self, key):
        if key in self.__immutables:
            raise ValueError("The value is immutable and cannot be changed.")

    def clone(self):
        """
        Clones the RequestContext creating a new RequestContext with the data
        copied from the original.  Observables / callbacks are not copied in the
        cloning process.

        :return: a new RequestContext
        """
        return RequestContext(values=self.__store, immutables=self.__immutables)

    def immutable(self, key, value):
        """Sets the given value and makes it immutable for the
        lifetime of the request context.  If someone tries to change
        the value then a ValueError is raised.
        """
        self.__check_immutable(key)
        self[key] = value
        self.__immutables.add(key)

    def contains_listener(self, listener):
        return listener in self.__observable

    def register_listener(self, listener):
        self.__observable.register(listener)

    def _activate(self):
        _request_store.context = self
        self.__active = True
        self.__observable("activate", self)

    def _release(self):
        if self.__active:
            # fire listener first because listeners may depend on
            # request to perform cleanup work
            self.__observable("deactivate", self)
            _request_store.release()
            self.__active = False


class RequestContextManager(object):

    def __init__(self, request_context=None):
        # None check required because request_context acts like a dict
        self.__request_context = request_context if request_context is not None else RequestContext()
        self.__nesting = 0

    @contextmanager
    def context_manager(self):
        if self.__nesting == 0:
            self.__request_context._activate()
        self.__nesting += 1
        try:
            yield
        except Exception as e:
            # on exception release immediately
            self.__nesting = 0
            self.__request_context._release()
            logger.warn("Encounter an exception in request context manager.")
            raise e
        else:
            if self.__nesting <= 0:
                # should not happen but handle for safety
                self.__nesting = 0
                self.__request_context._release()
                logger.warn("Request context release called without active context.")
            else:
                self.__nesting -= 1
                if self.__nesting == 0:
                    self.__request_context._release()

    @staticmethod
    def active():
        return _request_store.active

    @staticmethod
    def get_context():
        if not _request_store.active:
            raise RequestContextError("No request context found for executing stack.")
        return _request_store.context


class ProxyHandlerMetaClass(type):

    def __init__(cls, name, base, dct):
        super().__init__(name, base, dct)
        setattr(cls, "__getattribute__", ProxyHandlerMetaClass.__getattribute)

    @staticmethod
    def request_proxy(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            request_context = None
            if hasattr(method.__self__, "_request_context"):
                request_context = method.__self__._request_context
            with StackContext(RequestContextManager(request_context).context_manager):
                return method(*args, **kwargs)
        return wrapper

    @staticmethod
    def __getattribute(obj, name):
        attr = object.__getattribute__(obj, name)
        if name in object.__getattribute__(obj, "PROXY_METHODS"):
            if hasattr(obj, "STORE_CONTEXT_ON_OBJECT") and not hasattr(obj, "_request_context"):
                obj._request_context = RequestContext()
            attr = ProxyHandlerMetaClass.request_proxy(attr)
        return attr


class SocketHandlerProxyMixin(metaclass=ProxyHandlerMetaClass):

    STORE_CONTEXT_ON_OBJECT = True
    PROXY_METHODS = ("open", "on_message", "on_close")


class SocketRequestHandlerProxyMixin(metaclass=ProxyHandlerMetaClass):

    PROXY_METHODS = ("open", "on_message", "on_close")


class WebRequestHandlerProxyMixin(metaclass=ProxyHandlerMetaClass):

    PROXY_METHODS = "_execute"
