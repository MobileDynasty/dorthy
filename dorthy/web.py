import functools
import logging
import traceback
import urllib
import urllib.parse

from collections import namedtuple
from functools import partial

from tornado.escape import json_decode
from tornado.web import RequestHandler, HTTPError

from dorthy import template
from dorthy.enum import DeclarativeEnum
from dorthy.json import jsonify
from dorthy.session import session_store, Session
from dorthy.request import WebRequestHandlerProxyMixin
from dorthy.security import SecurityManager, AccessDeniedError, AuthenticationException
from dorthy.settings import config
from dorthy.utils import native_str


logger = logging.getLogger(__name__)

ErrorResponse = namedtuple("ErrorResponse",
                           ["status_code", "message", "exception", "stack"])


class MediaTypes(DeclarativeEnum):

    HTML = "text/html"
    JSON = "application/json"


def consumes(media=MediaTypes.JSON, arg_name="model"):

    class _Consumes(object):

        def __init__(self, method):
            self._method = method
            self.__doc__ = method.__doc__
            self.__name__ = method.__name__

        def __get__(self, obj, type=None):
            return partial(self, obj)

        def __call__(self, *args, **kwargs):
            m_self = args[0]
            # check for proper content type
            if not m_self.request.headers.get("Content-Type", "").startswith(media.value):
                raise HTTPError(400, "Invalid Content-Type received.")
            if media == MediaTypes.JSON:
                # parse json
                kwargs[arg_name] = json_decode(m_self.request.body)
            else:
                raise HTTPError(500, "MediaType not supported.")
            return self._method(*args, **kwargs)

    return _Consumes


def produces(media=MediaTypes.JSON, root=None, camel_case=True, ignore_attributes=None):

    class _Produces(object):

        def __init__(self, method):
            self.__method = method
            self.__doc__ = method.__doc__
            self.__name__ = method.__name__

        def __get__(self, obj, type=None):
            return partial(self, obj)

        def __call__(self, *args, **kwargs):
            m_self = args[0]
            m_self.media_type = media
            m_self.set_header("Content-Type", media.value)
            val = self.__method(*args, **kwargs)
            if val and not m_self.finished:
                if media == MediaTypes.JSON:
                    m_self.write(jsonify(val,
                                         root=root,
                                         camel_case=camel_case,
                                         ignore_attributes=ignore_attributes))
                elif media == MediaTypes.HTML:
                    m_self.write(val)
            return None

    return _Produces


def render(method):

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        val = method(self, *args, **kwargs)
        if val and not self.finished:
            if isinstance(val, str):
                self.render(val)
            else:
                self.render(val[0], **val[1])
    return wrapper


def redirect(method):

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        val = method(self, *args, **kwargs)
        if val and not self.finished:
            self.redirect(val)
    return wrapper


class BaseHandler(RequestHandler, WebRequestHandlerProxyMixin):

    SESSION_COOKIE_KEY = "s"

    DEFAULT_SESSION_TIMEOUT = 1800
    if "web.session_timeout" in config:
        DEFAULT_SESSION_TIMEOUT = config.web.get("session_timeout", 1800)

    COOKIE_DOMAIN = None
    if "web.cookie_domain" in config:
        COOKIE_DOMAIN = config.web.cookie_domain

    USE_SECURE_COOKIE = True if "web.cookie_secret" in config and config.web.enabled("cookie_secret") else False

    def __init__(self, application, request, **kwargs):
        self.media_type = MediaTypes.HTML
        self.application = application
        self._request_finished = False
        self.__session = None
        self.__debug = "debug" in self.application.settings and \
                       self.application.settings["debug"]
        self.__client_ip = None

        # initialize framework template system -- replace tornado's
        if "template_conf" in self.application.settings:
            self.require_setting("template_path", feature="@dorthy.web.template.engine")
            conf = dict(self.application.settings["template_conf"])
            conf["auto_reload"] = self.__debug
            template.config_environment(self.get_template_path(), **conf)
            self.__use_framework_templates = True

        super().__init__(application, request, **kwargs)

    @property
    def client_ip(self):
        """
        Provides a method to retrieve the client ip address
        behind a load balancer (ELB)
        """
        if not self.__client_ip:
            ip = self.request.headers.get("X-Forwarded-For", self.request.remote_ip)
            self.__client_ip = ip.split(",")[0].strip()
        return self.__client_ip

    @property
    def debug(self):
        return self.__debug

    @property
    def finished(self):
        return self._finished

    def get_user_agent(self):
        return self.request.headers.get("User-Agent")

    def get_current_user(self):
        if SecurityManager().authenticated():
            return SecurityManager().get_principal()
        else:
            return None

    def get_user_locale(self):
        principal = self.get_current_user()
        if principal is not None:
            return principal.locale
        else:
            return None

    def set_secure_cookie(self, name, value, expires_days=None,
                          domain=None, expires=None, path="/", **kwargs):

        if domain is None and self.COOKIE_DOMAIN is not None:
            domain = self.COOKIE_DOMAIN

        super().set_secure_cookie(name,
                                  value,
                                  expires_days=expires_days,
                                  domain=domain,
                                  expires=expires,
                                  path=path,
                                  **kwargs)

    def set_nocache_headers(self):
        self.set_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.set_header('Pragma', 'no-cache')
        self.set_header('Expires', 0)

    def clear_session(self):
        session = self.get_session()
        if session is not None:
            session.invalidate()

    def get_session(self, create=False, timeout=DEFAULT_SESSION_TIMEOUT, update_access=True):
        if self.__session is None:
            session_id = self.__get_session_cookie()
            if session_id:
                self.__session = session_store.load(native_str(session_id))
            if self.__session is None and create:
                self.__session = Session(session_store.generate_session_id(),
                                         timeout=timeout,
                                         update_access=update_access)
                self.__set_session_cookie()
        return self.__session

    def __get_session_cookie(self):
        if self.USE_SECURE_COOKIE:
            return self.get_secure_cookie(self.SESSION_COOKIE_KEY)
        else:
            return self.get_cookie(self.SESSION_COOKIE_KEY)

    def __set_session_cookie(self):
        if self.__session is not None:
            if self.USE_SECURE_COOKIE:
                self.set_secure_cookie(self.SESSION_COOKIE_KEY, self.__session.session_id)
            else:
                self.set_cookie(self.SESSION_COOKIE_KEY, self.__session.session_id)
        else:
            logger.warn("Set Session cookie called for empty session.")

    def __save_session(self):
        # load the session if it exists so that the session
        # store can update its timestamp / expiration period
        session = self.get_session()
        if session is not None:
            session_store.save(session)
            if not session.valid:
                self.clear_cookie(self.SESSION_COOKIE_KEY)
        elif self.__get_session_cookie():
            self.clear_cookie(self.SESSION_COOKIE_KEY)

    def on_finish(self):
        pass

    def render(self, template_name, **kwargs):
        """
        Renders the given template using the passed keyword args

        :param template_name: the template name
        :param kwargs: keyword args passed to the template
        """
        if self.__use_framework_templates:
            temp = template.get_template(self.get_template_path(), template_name)
            namespace = dict(
                handler=self,
                request=self.request,
                current_user=self.current_user,
                locale=self.locale,
                static_url=self.static_url,
                xsrf_form_html=self.xsrf_form_html,
                reverse_url=self.reverse_url
            )
            namespace.update(kwargs)
            rendered = temp.render(namespace)
            self.finish(rendered)
        else:
            super().render(template_name, kwargs)

    def finish(self, chunk=None):
        if not self._request_finished:
            # prevents a recursive loop on finish if exception raised
            self._request_finished = True
            self.__save_session()
            self.on_finish()
        super().finish(chunk)

    def write_error(self, status_code, **kwargs):

        e = stack = None
        exc_info = kwargs.get("exc_info", None)

        if status_code == 401:
            message = "User not authorized."
        elif status_code == 403:
            message = "User forbidden."
        else:
            if exc_info:
                if isinstance(exc_info[1], AccessDeniedError):
                    status_code = 403
                    message = "User forbidden."
                    self.set_status(403, message)
                elif isinstance(exc_info[1], AuthenticationException):
                    status_code = 401
                    message = "User not authorized."
                    self.set_status(401, message)
                else:
                    t, e, tb = exc_info
                    stack = traceback.format_tb(tb)
                    message = str(e) if self.debug else "An internal server error occurred."
            else:
                message = "An unknown error occurred."

        error = ErrorResponse(status_code=status_code,
                              message=message,
                              exception=e.__class__.__name__ if self.debug and e else None,
                              stack=stack if self.debug and stack else None)

        if self.media_type == MediaTypes.JSON:
            self.set_header("Content-Type", MediaTypes.JSON.value)
            self.write(jsonify(error._asdict(), "error"))
        else:
            if self.debug:
                self.render("error/error-dev.html", error=error)
            else:
                self.render("error/error.html", error=error)


class TemplateHandler(BaseHandler):

    def initialize(self, template, status=None):
        self.template = template
        self.status = status

    def get(self):
        if self.status:
            self.set_status(self.status)
        self.render(self.template)


def authenticated(redirect=False):

    class _Authenticated(object):

        def __init__(self, method):
            self.__method = method
            self.__doc__ = method.__doc__
            self.__name__ = method.__name__

        def __get__(self, obj, type=None):
            return partial(self, obj)

        def __call__(self, handler, *args, **kwargs):
            if not SecurityManager().authenticated():
                SecurityManager().load_context(handler)
                if not SecurityManager().authenticated():
                    if redirect and handler.request.method in ("GET", "POST", "HEAD"):
                        url = handler.get_login_url()
                        if "?" not in url:
                            if urllib.parse.urlsplit(url).scheme:
                                next_url = handler.request.full_url()
                            else:
                                next_url = handler.request.uri
                            url += "?" + urllib.parse.urlencode(dict(next=next_url))
                        handler.redirect(url)
                        return
                    raise HTTPError(401, "User not authorized.")

            return self.__method(handler, *args, **kwargs)

    return _Authenticated
