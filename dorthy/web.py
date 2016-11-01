import inspect
import logging
import traceback
import urllib
import urllib.parse

from collections import namedtuple

from decorator import decorator

from tornado.escape import to_basestring
from tornado.web import RequestHandler, HTTPError

from dorthy import template
from dorthy.enum import DeclarativeEnum
from dorthy.json import jsonify
from dorthy.security.auth import AuthorizationHeaderToken
from dorthy.session import session_store, Session
from dorthy.request import WebRequestHandlerProxyMixin
from dorthy.security import SecurityManager, AccessDeniedError, AuthenticationException
from dorthy.settings import config
from dorthy.utils import native_str, parse_json


logger = logging.getLogger(__name__)

ErrorResponse = namedtuple("ErrorResponse",
                           ["status_code", "message", "exception", "stack"])


class MediaTypes(DeclarativeEnum):

    HTML = "text/html"
    JSON = "application/json"


def consumes(media=MediaTypes.JSON, arg_name="model",
             request_arg=None, optional_request_arg=False, underscore_case=True, object_dict_wrapper=True):

    def _parse_json(handler):
        if request_arg is None:
            s = to_basestring(handler.request.body)
        else:
            arg = handler.get_argument(request_arg, None)
            if arg is None and not optional_request_arg:
                raise HTTPError(400, "Argument missing: {}".format(request_arg))
            s = to_basestring(arg)
        return parse_json(s, underscore_case=underscore_case, object_dict_wrapper=object_dict_wrapper) if s else None

    def _consumes(f, handler, *args, **kwargs):

        # check for proper content type if request_arg is not set
        # if request_arg is set assume mixed content -- i.e. files and data
        if request_arg is None and not handler.request.headers.get("Content-Type", "").startswith(media.value):
            raise HTTPError(400, "Invalid Content-Type received.")

        if media == MediaTypes.JSON:
            # check keyword args first
            if arg_name in kwargs:
                kwargs[arg_name] = _parse_json(handler)
            else:
                sig = inspect.signature(f)
                params = sig.parameters
                for indx, (name, param) in enumerate(params.items()):
                    if name == arg_name or \
                            (param.annotation != inspect.Parameter.empty and param.annotation == "model"):
                        args = list(args)
                        args[indx - 1] = _parse_json(handler)
                        break

                    # model param not contained in method signature
                    if indx == len(args):
                        raise TypeError("No model argument found in method signature")
        else:
            raise HTTPError(500, "MediaType not supported.")

        return f(handler, *args, **kwargs)

    return decorator(_consumes)


def produces(media=MediaTypes.JSON, root=None, camel_case=True, ignore_attributes=None):

    def _produces(f, handler, *args, **kwargs):
        handler.media_type = media
        result = f(handler, *args, **kwargs)
        handler.write_results(result,
                              media=media,
                              root=root,
                              camel_case=camel_case,
                              ignore_attributes=ignore_attributes)

    return decorator(_produces)


def mediatype(media=MediaTypes.JSON):

    def _mediatype(f, handler, *args, **kwargs):
        handler.media_type = media
        handler.set_header("Content-Type", media.value)
        return f(handler, *args, **kwargs)

    return decorator(_mediatype)


@decorator
def render(f, handler, *args, **kwargs):
    val = f(handler, *args, **kwargs)
    if val and not handler.finished:
        if isinstance(val, str):
            handler.render(val)
        else:
            handler.render(val[0], **val[1])


@decorator
def redirect(f, handler, *args, **kwargs):
    val = f(handler, *args, **kwargs)
    if val and not handler.finished:
        handler.redirect(val)


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

    def write_results(self, results, media=MediaTypes.JSON, root=None, camel_case=True, ignore_attributes=None):
        self.media_type = media
        self.set_header("Content-Type", media.value)
        if results and not self.finished:
            if media == MediaTypes.JSON:
                if root is None and "produces_wrapper" in self.application.settings:
                    root_wrapper = self.application.settings["produces_wrapper"]
                else:
                    root_wrapper = root
                self.write(jsonify(results,
                                   root=root_wrapper,
                                   camel_case=camel_case,
                                   ignore_attributes=ignore_attributes))
            elif media == MediaTypes.HTML:
                self.write(results)


class TemplateHandler(BaseHandler):

    def initialize(self, template, status=None):
        self.template = template
        self.status = status

    def get(self):
        if self.status:
            self.set_status(self.status)
        self.render(self.template)


def authenticated(redirect=False, allow_header_auth=False):

    def _authenticated(f, handler, *args, **kwargs):
        if not SecurityManager().authenticated():
            SecurityManager().load_context(handler)
            if not SecurityManager().authenticated():
                if allow_header_auth and authenticate_token(handler):
                    return f(handler, *args, **kwargs)
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
                raise AuthenticationException("User not authorized.")

        return f(handler, *args, **kwargs)

    def authenticate_token(handler):
        if "Authorization" in handler.request.headers:
            auth_headers = handler.request.headers.get_list("Authorization")
            # only support one auth header in a request
            if len(auth_headers) == 1:
                auth = auth_headers[0]
                parts = auth.strip().partition(" ")
                if parts[0] and parts[2]:
                    token = AuthorizationHeaderToken(parts[0], parts[2].strip(), handler)
                    auth_provider = SecurityManager().get_authentication_provider(token)
                    if auth_provider:
                        auth_provider.authenticate(token)
                        if SecurityManager().authenticated():
                            return True
                    else:
                        logger.warn("No authentication provider found for header: %s", auth)
        return False

    return decorator(_authenticated)
