import logging
import urllib.parse

from .auth import UsernamePasswordAuthenticationToken
from .core import AuthenticationException, SecurityManager

from dorthy.web import BaseHandler, render, redirect

logger = logging.getLogger(__name__)


class UserPasswordAuthHandler(BaseHandler):

    def _get_default_url(self):
        if "default_url" in self.application.settings:
            return self.application.settings["default_url"]
        else:
            return "/"

    @render
    def get(self):
        return "login.html", dict(next=self.get_argument("next", self._get_default_url()))

    @redirect
    def post(self):

        username = self.get_argument("username")
        password = self.get_argument("password")
        next_url = self.get_argument("next", self._get_default_url())

        try:
            token = UsernamePasswordAuthenticationToken(username, password)
            auth_provider = SecurityManager().get_authentication_provider(token)
            if not auth_provider:
                raise AuthenticationException("No authentication provider found for user authentication.")

            auth_provider.authenticate(token)
            if not SecurityManager().authenticated():
                raise AuthenticationException()

            SecurityManager().store_context(self)
        except AuthenticationException:
            logger.exception("Failed to authenticate username: %s", username)
            return self.request.path + "?" + urllib.parse.urlencode(dict(next=next_url))
        else:
            return next_url


class DefaultLogoutHandler(BaseHandler):

    @redirect
    def get(self):
        self.clear_session()
        return "/auth/login"
