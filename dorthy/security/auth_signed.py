import datetime
import hashlib
import logging
import sys

from .core import AuthenticationException
from .crypto import sign_message

from dorthy.utils import rfc_2822_timestamp, convert_from_rfc_2822, now, xstr


logger = logging.getLogger(__name__)


class SignedRequestAuthenticationToken(object):

    def __init__(self, token, request):
        self.token = token
        self.request = request

    @property
    def access_id(self):
        return self.token.split(":")[0]

    @property
    def signature(self):
        return self.token.split(":")[1]


class AbstractSignedRequestAuthenticationProvider(object):
    """This provides a signature request based authentication provider.
    """

    def __init__(self, ttl=120):
        self.__ttl = ttl

    def supports(self, authentication_token):
        if authentication_token and isinstance(authentication_token, SignedRequestAuthenticationToken):
            return True
        else:
            return False

    def authenticate(self, authentication_token):

        if not verify_request_ttl(authentication_token.request, self.__ttl):
            raise AuthenticationException("Request expired.")

        if not verify_http_request(authentication_token.request,
                                   authentication_token.signature,
                                   self._get_signing_key(authentication_token)):
            raise AuthenticationException("Invalid signature.")

        self._authenticate_user(authentication_token)

    def _authenticate_user(self, authentication_token):
        raise NotImplementedError()

    def _get_signing_key(self, authentication_token):
        raise NotImplementedError()


def sign_http_request(verb, uri_path, timestamp, signing_key, content_md5=None, query=None, encoding=None):
    if not encoding:
        encoding = sys.getdefaultencoding()
    if not isinstance(timestamp, str):
        timestamp = rfc_2822_timestamp(timestamp)
    if not isinstance(signing_key, bytes):
        signing_key = signing_key.encode(encoding)
    if isinstance(content_md5, bytes):
        content_md5 = content_md5.decode(encoding)
    msg = "{}\n{}\n{}\n{}\n{}".format(
        verb, uri_path, xstr(content_md5), xstr(query), timestamp).encode(encoding)
    return sign_message(signing_key, msg).decode(encoding)


def verify_http_request(request, request_signature, signing_key, encoding=None):
    if not encoding:
        encoding = sys.getdefaultencoding()
    if "Date" not in request.headers:
        raise AuthenticationException("No timestamp found in request.")
    timestamp = request.headers["Date"]
    content_md5 = None
    if request.body:
        content_md5 = hashlib.md5(request.body).hexdigest()
    signed_request = sign_http_request(request.method,
                                       request.path,
                                       timestamp,
                                       signing_key,
                                       content_md5=content_md5,
                                       query=request.query,
                                       encoding=encoding)
    return signed_request == request_signature


def verify_request_ttl(request, ttl=120):
    if "Date" not in request.headers:
        raise AuthenticationException("No timestamp found in request.")
    timestamp = convert_from_rfc_2822(request.headers["Date"])
    return timestamp + datetime.timedelta(seconds=ttl) >= now()