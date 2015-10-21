import inspect
import logging
import weakref

from collections import MutableMapping


logger = logging.getLogger(__name__)


class Singleton(object):
    """
    A decorated to implement the singleton pattern.
    This implementation is not thread safe.

    Based on: http://stackoverflow.com/questions/42558/python-and-the-singleton-pattern
    """

    def __init__(self, decorated_class):
        self.__decorated_class = decorated_class
        self.__doc__ = decorated_class.__doc__

    def __call__(self):
        """
        Returns the singleton instance.
        """
        try:
            return self.__instance
        except AttributeError:
            self.__instance = self.__decorated_class()
            if hasattr(self.__instance, "initialize"):
                self.__instance.initialize()
            return self.__instance


class MultipleObservableErrors(Exception):

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.__errors = errors

    @property
    def errors(self):
        return self.__errors


class Observable(object):
    """Provides an observable class the uses weak references so
    that objects are not held in memory by the observable.
    """

    def __init__(self, handle_errors=True):
        self.__listeners = dict()
        self.__handle_errors = handle_errors

    def __call__(self, *args, **kwargs):
        """Calls the listeners with the given arguments and
        keyword arguments.
        """
        if not self.__listeners:
            return

        errors = list()
        listeners = dict()
        for k, v in self.__listeners.items():
            call_obj = None
            if v[0] == "f":
                call_obj = v[2]
            elif v[0] == "m":
                obj = v[2]()
                if obj:
                    call_obj = getattr(obj, v[3].__name__)
            else:
                raise ValueError("Only supports functions or methods as listeners.")

            # execute callable
            if call_obj:
                listeners[v[1]] = v
                try:
                    call_obj(*args, **kwargs)
                except Exception as e:
                    if self.__handle_errors:
                        logger.exception("Failed to execute observable callback.")
                    else:
                        # collect the errors
                        errors.append(e)

        # clean out references that are no longer valid
        self.__listeners = listeners

        # raise exceptions generated
        if errors:
            raise MultipleObservableErrors("Failed to execute observable callbacks.", errors)

    def __contains__(self, item):
        if inspect.isfunction(item) or inspect.ismethod(item):
            return id(item) in self.__listeners
        else:
            return item in self.__listeners

    def register(self, listener):
        """Registers a listener with the observable class.  The
        listener must either be a method or a function.

        returns: the listener id that can be used to remove the listener
        """
        ref_key = id(listener)
        if inspect.isfunction(listener):
            ref = ("f", ref_key, listener)
        elif inspect.ismethod(listener):
            weak_obj = weakref.ref(listener.__self__)
            ref = ("m", ref_key, weak_obj, listener.__func__)
        else:
            raise ValueError("Only supports functions or methods as listeners.")

        self.__listeners[ref_key] = ref

        return ref_key

    def remove(self, listener_id):
        """Removes the listener for the given id.

        returns: True if the listener has been found and removed, otherwise False
        """
        return True if self.__listeners.pop(listener_id, None) else False


class ObjectMap(MutableMapping):
    """Converts object attribute access to a
    map view.
    """

    def __init__(self, obj, ignore_=True):
        self.__object = obj
        self.__ignore_ = ignore_

    def _get_attrs(self):
        if self.__ignore_:
            return [d for d in dir(self.__object) if not d.startswith("_")]
        else:
            return dir(self.__object)

    def _check_key(self, key):
        if self.__ignore_ and key.startswith("_"):
            raise KeyError("Invalid attribute: " + key)

    def __contains__(self, key):
        self._check_key(key)
        return hasattr(self.__object, key)

    def __len__(self):
        return len(self._get_attrs())

    def __getitem__(self, key):
        self._check_key(key)
        try:
            return getattr(self.__object, key)
        except AttributeError:
            raise KeyError(key)

    def __delitem__(self, key):
        self._check_key(key)
        try:
            delattr(self.__object, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        self._check_key(key)
        setattr(self.__object, key, value)

    def __iter__(self):
        return iter(self._get_attrs())


class ObjectDict(dict):
    """Extends dict to provide object attribute get and set access.
    """

    def __delattr__(self, name):
        if name in self:
            del self[name]

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value
