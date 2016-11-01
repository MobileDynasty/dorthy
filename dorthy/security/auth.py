import logging

from .core import AuthenticationException

logger = logging.getLogger(__name__)


class AuthorizationHeaderToken(object):

    def __init__(self, scheme, token, handler):
        self.__scheme = scheme
        self.__token = token
        self.__handler = handler

    @property
    def scheme(self):
        return self.__scheme

    @property
    def token(self):
        return self.__token

    @property
    def handler(self):
        return self.__handler


class UsernamePasswordAuthenticationToken(object):

    def __init__(self, username, password):
        if not username:
            raise AuthenticationException("Username cannot be None.")
        self.username = username
        self.password = password


class UserTokenAuthenticationToken(object):

    def __init__(self, token):
        self.token = token

    @property
    def user_uid(self):
        return self.token.split(":")[0]

    @property
    def security_token(self):
        return self.token.split(":")[1]


class AbstractUserTokenAuthenticationProvider(object):
    """This provides a very basic shared key authentication system.
    """

    def supports(self, authentication_token):
        if authentication_token and isinstance(authentication_token, UserTokenAuthenticationToken):
            return True
        else:
            return False

    def authenticate(self, authentication_token):

        if not authentication_token.user_uid or not authentication_token.security_token:
            raise AuthenticationException("Invalid authentication token.")

        self._authenticate_user(authentication_token)

    def _authenticate_user(self, authentication_token):
        raise NotImplementedError()

