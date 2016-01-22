import base64
import threading

import json
import logging
import inspect
import pickle
import sys

from collections import Iterable, namedtuple
from contextlib import contextmanager

from decorator import decorator

from dorthy.dp import Singleton, ObjectMap
from dorthy.json import jsonify
from dorthy.request import RequestContextManager, RequestContextError
from dorthy.utils import create_set, native_str

from .access import AuthorityJSONSerializer, GroupVoter, UnanimousDecisionManager

logger = logging.getLogger(__name__)


class AuthenticationException(Exception):
    pass


class SecurityException(Exception):
    pass


class PrincipalJSONSerializer(object):
    """Serializes and de-serializes a principal object.
    """

    def deserialize(self, data):
        """De-serializes a principle

        Args:
            data: the principal represented either as a JSON string
            or a dictionary
        """
        dct = data if isinstance(data, dict) else json.loads(native_str(data))
        uid = dct["uid"]
        name = dct["name"]
        locale = dct.get("locale", None)
        timezone = dct.get("timezone", None)
        return Principal(uid, name, locale, timezone)

    def serialize(self, principal):
        """Serializes a principal into a JSON string

        Args:
            principal: the principal object
        """
        return jsonify(principal)


class Principal(object):
    """The principal object used to store basic information
    as well as access permissions and groups.
    """

    def __init__(self, uid, name, locale=None, timezone=None):
        self.__uid = uid
        self.__name = name
        self.__locale = locale
        self.__timezone = timezone

    def __eq__(self, other):
        if not other:
            return False
        if type(other) is not Principal:
            return False
        if self is other:
            return True
        if self.__uid == other.uid:
            return True
        return False

    def __hash__(self):
        return hash(self.__uid)

    @property
    def uid(self):
        return self.__uid

    @property
    def name(self):
        return self.__name

    @property
    def locale(self):
        return self.__locale

    @property
    def timezone(self):
        return self.__timezone


class GroupJSONSerializer(object):
    """Serializes and de-serializes a group object.
    """

    def deserialize(self, data):
        """De-serializes a group

        Args:
            data: the group represented either as a JSON string
            or a dictionary
        """
        dct = data if isinstance(data, dict) else json.loads(native_str(data))
        name = dct["name"]
        group_type = dct.get("group_type", None)
        security_group = dct.get("security_group", False)
        primary = dct.get("primary", False)
        effective_date = dct.get("effective_date", None)
        end_date = dct.get("end_date", None)
        attributes = dct.get("attributes", None)
        return Group(name,
                     group_type=group_type,
                     security_group=security_group,
                     primary=primary,
                     effective_date=effective_date,
                     end_date=end_date,
                     attributes=attributes)

    def serialize(self, group):
        """Serializes a group into a JSON string

        Args:
            group: the group object
        """
        return jsonify(group)


class Group(object):

    def __init__(self, name, group_type=None, security_group=False, primary=False,
                 effective_date=None, end_date=None, attributes=None):
        self.__name = name
        self.__group_type = group_type
        self.__security_group = security_group
        self.__primary = primary
        self.__effective_date = effective_date
        self.__end_date = end_date
        self.__attributes = attributes

    def __eq__(self, other):
        if not other:
            return False
        if type(other) is not Group:
            return False
        if self is other:
            return True
        if self.name == other.name and \
                self.group_type == other.group_type:
            return True
        return False

    def __hash__(self):
        value = hash(self.__name)
        if self.__group_type is not None:
            value = (value << 1) ^ hash(self.__group_type)
        return value

    @property
    def name(self):
        return self.__name

    @property
    def group_type(self):
        return self.__group_type

    @property
    def security_group(self):
        return self.__security_group

    @property
    def effective_date(self):
        return self.__effective_date

    @property
    def end_date(self):
        return self.__end_date

    @property
    def attributes(self):
        return self.__attributes

    @property
    def primary(self):
        return self.__primary


class Authentication(object):

    def __init__(self, principal):
        self.__principal = principal

    def get_authorities(self):
        pass

    def get_groups(self):
        pass

    def get_primary_group(self):
        return next((g for g in self.get_groups() if g.primary), None)

    def get_principal(self):
        return self.__principal

    def is_authenticated(self):
        return True

    @property
    def principal(self):
        return self.get_principal()


class HTTPSessionSecurityContextRepository(object):

    def __init__(self, serializer):
        self.__serializer = serializer

    def clear_context(self, request):
        session = request.get_session(create=False)
        if session and "security_context" in session:
            del session["security_context"]

    def load_context(self, request):
        session = request.get_session()
        if session and "security_context" in session:
            try:
                context_data = session["security_context"]
                return self.__serializer.deserialize(context_data)
            except:
                logger.exception("Failed to load security context.")
                del session["security_context"]
        return None

    def save_context(self, context, request):
        session = request.get_session(create=True)
        context_data = self.__serializer.serialize(context)
        session["security_context"] = context_data


class InMemorySecurityContextStore(object):

    def __init__(self):
        self.__store = dict()

    def clear_context(self):
        self.__store.clear()

    def active(self):
        return "security_context" in self.__store

    def get_context(self):
        return self.__store.get("security_context", None)

    def set_context(self, context):
        self.__store["security_context"] = context

    def load_context(self):
        return self.__store.get("security_context", None)

    def save_context(self, context):
        self.__store["security_context"] = context


class RequestContextSecurityContextManager(object):

    def _assert_request_context(self):
        if not RequestContextManager.active():
            raise RequestContextError("Authentication provider cannot access request context.")

    def clear_context(self):
        self._assert_request_context()
        if "security_context" in RequestContextManager.get_context():
            del RequestContextManager.get_context()["security_context"]

    def active(self):
        return RequestContextManager.active() and \
            "security_context" in RequestContextManager.get_context()

    def get_context(self):
        self._assert_request_context()
        return RequestContextManager.get_context().get("security_context", None)

    def set_context(self, context):
        self._assert_request_context()
        RequestContextManager.get_context()["security_context"] = context


class SimpleAuthentication(Authentication):

    def __init__(self, principal, authorities=None, groups=None):
        super().__init__(principal)
        self.authorities = create_set(authorities)
        self.groups = create_set(groups)

    def get_authorities(self):
        return self.authorities

    def get_groups(self):
        return self.groups


class SimpleAuthenticationJSONSerializer(object):

    def deserialize(self, data):
        dct = json.loads(native_str(data))
        principal = PrincipalJSONSerializer().deserialize(dct["principal"])
        groups = self._deserialize_list(dct.get("groups", None), GroupJSONSerializer)
        authorities = self._deserialize_list(dct.get("authorities", None), AuthorityJSONSerializer)
        return SimpleAuthentication(principal, authorities, groups)

    def serialize(self, authentication):
        return jsonify(authentication)

    def _deserialize_list(self, data, serializer_cls):
        if data:
            l = list()
            serializer = serializer_cls()
            for d in data:
                l.append(serializer.deserialize(d))
            return l
        return None


class AuthenticationPickleSerializer(object):

    _SYS_ENCODING = sys.getdefaultencoding()

    def deserialize(self, data):
        b = data.encode(self._SYS_ENCODING)
        pickled = base64.standard_b64decode(b)
        return pickle.loads(pickled)

    def serialize(self, authentication):
        pickled = pickle.dumps(authentication)
        return base64.standard_b64encode(pickled).decode(self._SYS_ENCODING)


ADMIN_GROUP = Group("root", security_group=True)


class DevAuthenticationProvider(object):

    def authenticate(self, authentication_token):
        assert authentication_token, "No authentication token provided"
        principal = Principal(-1, authentication_token.username)
        auth = SimpleAuthentication(principal, groups=ADMIN_GROUP)
        SecurityManager().set_authentication(auth)

    def supports(self, authentication_token):
        return hasattr(authentication_token, "username")


_IN_MEMORY_CONTEXT_STORE = InMemorySecurityContextStore()

SECURITY_MANAGER_DEFAULTS = {
    "AUTHENTICATION_PROVIDERS": (DevAuthenticationProvider(), ),
    "ACCESS_DECISION_MANAGER": UnanimousDecisionManager(GroupVoter(ADMIN_GROUP)),
    "SECURITY_CONTEXT_REPOSITORY": _IN_MEMORY_CONTEXT_STORE,
    "SECURITY_CONTEXT_MANAGER": _IN_MEMORY_CONTEXT_STORE,
    "OPTIONS": {}
}


class ThreadLocalAccessHistory(threading.local):

    def __init__(self):
        super().__init__()
        self.__history = list()

    @property
    def history(self):
        return self.__history

    def release(self):
        del self.__history[:]

_local_access_history = ThreadLocalAccessHistory()


class RequestContextAccessHistory(object):

    CONTEXT_KEY = "_access_history"

    @property
    def history(self):
        rc = RequestContextManager.get_context()
        if self.CONTEXT_KEY not in rc:
            access_history = list()
            rc.immutable(self.CONTEXT_KEY, access_history)
        else:
            access_history = rc[self.CONTEXT_KEY]
        return access_history

    def release(self):
        del self.history[:]


class AccessHistory(object):

    def __init__(self):
        self.__request_store = RequestContextAccessHistory()

    def __len__(self):
        return len(self.get_requests())

    def get_requests(self):
        access_store = self.__request_store if RequestContextManager.active() else _local_access_history
        return access_store.history

    def pop_request(self):
        self.get_requests().pop()

    def push_request(self, access_request):
        self.get_requests().append(access_request)


AccessRequest = namedtuple("AccessRequest",
                           ["expression", "authorized_attribute"])


@Singleton
class SecurityManager(object):

    CONFIG_VARIABLES = ("AUTHENTICATION_PROVIDERS", "ACCESS_DECISION_MANAGER", "SECURITY_CONTEXT_REPOSITORY",
                        "SECURITY_CONTEXT_MANAGER", "OPTIONS")

    def __init__(self):
        self.config_from_object(SECURITY_MANAGER_DEFAULTS, inherit=False)
        self.__access_history = AccessHistory()

    def config_from_object(self, obj, inherit=True):
        if inspect.ismodule(obj):
            config = ObjectMap(obj)
        elif isinstance(obj, dict):
            config = obj
        else:
            raise ValueError("Security config is not a supported type")
        if not inherit:
            self.__config = dict()
        for key, value in config.items():
            if key in self.CONFIG_VARIABLES:
                self.__config[key] = value

    @property
    def authentication_providers(self):
        return self.__config["AUTHENTICATION_PROVIDERS"]

    @property
    def access_decision_manager(self):
        return self.__config["ACCESS_DECISION_MANAGER"]

    @property
    def access_history(self):
        return self.__access_history

    @property
    def security_context_repository(self):
        return self.__config["SECURITY_CONTEXT_REPOSITORY"]

    @property
    def security_context_manager(self):
        return self.__config["SECURITY_CONTEXT_MANAGER"]

    @property
    def options(self):
        try:
            return self.__config["OPTIONS"]
        except KeyError:
            return {}

    def active(self):
        return self.security_context_manager.active()

    def authenticated(self):
        return self.active() and self.security_context_manager.get_context().is_authenticated()

    def get_authentication_provider(self, authentication_token):
        if isinstance(self.authentication_providers, Iterable):
            return next((p for p in self.authentication_providers if p.supports(authentication_token)), None)
        else:
            return self.authentication_providers \
                if self.authentication_providers.supports(authentication_token) else None

    def get_authentication(self):
        if not self.authenticated():
            raise AuthenticationException("Not Authenticated")
        return self.security_context_manager.get_context()

    def set_authentication(self, authentication):
        assert authentication, "Authentication cannot be None"
        self.security_context_manager.set_context(authentication)

    def get_principal(self):
        return self.get_authentication().principal

    def authorized(self, expression, attribute=None):
        self.access_decision_manager.decide(self.get_authentication(),
                                            expression,
                                            self.access_history,
                                            attribute=attribute,
                                            **self.options)

    def clear_context(self, *args, **kwargs):
        self.security_context_manager.clear_context()
        self.security_context_repository.clear_context(*args, **kwargs)

    def load_context(self, *args, **kwargs):
        security_context = self.security_context_repository.load_context(*args, **kwargs)
        if security_context:
            self.security_context_manager.set_context(security_context)

    def store_context(self, *args, **kwargs):
        if not self.active():
            raise SecurityException("Cannot store security context - no context active")
        self.security_context_repository.save_context(
            self.get_authentication(), *args, **kwargs)


AuthorizedAttribute = namedtuple("AuthorizedAttribute", ["f", "args", "kwargs"])


def authorized(expression=None, arg_name="authentication"):
    """
    Decorator that is used to check authorization.

    :param expression: the security expression. If no expression is passed
    then the system just checks to see if a user is authenticated in the system.

    :param arg_name: the optional argument name used to inject the authentication
    object into a method or function that is decorated.
    """
    def _authorized(f, *args, **kwargs):

        authorized_attribute = AuthorizedAttribute(f=f, args=args, kwargs=kwargs)
        with authorized_context(expression=expression, authorized_attribute=authorized_attribute) as authentication:

            # passes the authentication object to the method call if it exists in the args or kwargs
            if arg_name in kwargs:
                kwargs[arg_name] = authentication
            else:
                sig = inspect.signature(f)
                params = sig.parameters
                for indx, (name, param) in enumerate(params.items()):
                    if indx == len(args):
                        break
                    if name == arg_name or \
                            (param.annotation != inspect.Parameter.empty and param.annotation == "auth"):
                        args = list(args)
                        args[indx] = authentication
                        break

            return f(*args, **kwargs)

    return decorator(_authorized)


@contextmanager
def authorized_context(expression=None, authorized_attribute=None):
    """
    Authorized context
    :param expression: the expression
    :param authorized_attribute: authorized attributes
    """

    if not SecurityManager().authenticated():
        raise AuthenticationException("Not Authenticated")

    access_history = SecurityManager().access_history
    access_history.push_request(AccessRequest(expression=expression, authorized_attribute=authorized_attribute))

    try:
        if expression is not None:
            SecurityManager().authorized(expression, attribute=authorized_attribute)

        yield SecurityManager().get_authentication()

    finally:
        access_history.pop_request()

