import base64
import time
import logging
import zlib

from functools import partial

import raven
from raven.base import Client
from raven.utils import get_auth_header

from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from raven.contrib.tornado import SentryMixin

from dorthy.json import jsonify
from dorthy.security import SecurityManager

logger = logging.getLogger(__name__)


class TornadoSentryClient(Client):
    """Initial inspiration from raven.contrib.tornado
    but the raven version is broken for handling errors out
    of the AsyncHTTPClient and does not support disabling
    SSL server cert validation.
    """

    def __init__(self, dsn=None, host_id=None, validate_cert=False, **options):
        super().__init__(dsn=dsn, **options)
        self.__host_id = host_id
        self.__validate_cert = validate_cert

    @property
    def host_id(self):
        return self.__host_id if self.__host_id else ""

    def capture(self, *args, **kwargs):
        """
        Takes the same arguments as the super function in :py:class:`Client`
        and extracts the keyword argument callback which will be called on
        asynchronous sending of the request

        :return: a 32-length string identifying this event and checksum
        """
        if not self.is_enabled():
            return

        data = self.build_msg(*args, **kwargs)

        self.send(callback=kwargs.get('callback', None), **data)

        return data['event_id'],

    def encode(self, data):
        """
        Serializes ``data`` into a raw string.
        """
        return base64.b64encode(zlib.compress(jsonify(data).encode('utf8')))

    def send(self, auth_header=None, callback=None, **data):
        """
        Serializes the message and passes the payload onto ``send_encoded``.
        """

        try:
            message = self.encode(data)
        except TypeError:
            data = {"message": "Failed to serialize data for message. See server for details. Host ID: {}".
                    format(self.host_id)}
            message = self.encode(data)

        return self.send_encoded(message, auth_header=auth_header, callback=callback)

    def send_encoded(self, message, auth_header=None, **kwargs):
        """
        Given an already serialized message, signs the message and passes the
        payload off to ``send_remote`` for each server specified in the servers
        configuration.

        callback can be specified as a keyword argument
        """
        if not auth_header:
            timestamp = time.time()
            auth_header = get_auth_header(
                protocol=self.protocol_version,
                timestamp=timestamp,
                client='raven-python/%s' % (raven.VERSION,),
                api_key=self.public_key,
                api_secret=self.secret_key,
            )

        for url in self.servers:
            headers = {
                'X-Sentry-Auth': auth_header,
                'Content-Type': 'application/octet-stream',
            }

            self.send_remote(
                url=url, data=message, headers=headers,
                callback=kwargs.get('callback', None)
            )

    def send_remote(self, url, data, headers=None, callback=None):

        if not self.state.should_try():
            message = self._get_log_message(data)
            self.error_logger.error(message)
            return

        # TODO: implement retry logic -- the base implementation does
        # not work for asynchronous tornado processing.  It is based on
        # a singleton pattern for the client.
        self._send_remote(url, data, headers=headers, callback=callback)
        self.state.set_success()

    def _send_remote(self, url, data, headers=None, callback=None):

        if headers is None:
            headers = dict()

        # disable cert validation
        request = HTTPRequest(url,
                              method="POST",
                              body=data,
                              headers=headers,
                              validate_cert=self.__validate_cert)

        AsyncHTTPClient().fetch(request,
                                callback=partial(self._handle_response, url, data, callback))

    def _handle_response(self, url, data, callback, response):

        if response.error:
            self.error_logger.error(
                'Unable to reach Sentry log server: %s - Error Code: %s Message: %s',
                url, str(response.code), str(response.error)
            )
            message = self._get_log_message(data)
            self.error_logger.error('Failed to submit message: %r', message)
            return

        # try and process possible callback
        if callback and callable(callback):
            try:
                callback(response)
            except:
                self.error_logger.exception("Failed to process callback.")


class TornadoSentryMixin(SentryMixin):
    """
    A Sentry Mixin class for base tornado
    """

    def get_sentry_user_info(self):
        """
        Data for sentry.interfaces.User

        Default implementation only sends `is_authenticated` by checking if
        `tornado.web.RequestHandler.get_current_user` tests postitively for on
        Truth calue testing
        """
        auth = SecurityManager().get_authentication() if SecurityManager().authenticated() else None
        return {
            'sentry.interfaces.User': {
                'is_authenticated': True if auth else False,
                'id': auth.principal.uid if auth else None,
                'principal': auth.principal.name if auth else None
            }
        }


class SockJSSentryMixin(TornadoSentryMixin):
    """
    A SentryMixin class specifically for use with sockjs handler
    """
    
    def get_sentry_client(self):
        """
        Returns the sentry client configured in the application.
        Need to set sentry_client var during server setup
        i.e.:
        application.sentry_client = AsyncSentryClient(config.app.sentry.server)
        application.SocketRouter.sentry_client = application.sentry_client
        """
        return getattr(self.session.server, 'sentry_client', None)
    
    def get_sentry_data_from_request(self):
        """
        Extracts the data required for 'sentry.interfaces.Http' from the
        SockJS ConnectionInfo object

        :param return: A dictionary.
        """
        return {
            'sentry.interfaces.Http': {
                'url': self.request.path,
                'method': 'SOCKJS',
                'data': self.request.arguments,
                'cookies': self.request.cookies,
                'headers': dict(self.request.headers),
                'env': {
                    'REMOTE_ADDR': self.request.ip,
                }
            }
        }
    
    def get_default_context(self):
        data = {}

        # Update request data
        data.update(self.get_sentry_data_from_request())

        # update user data
        data.update(self.get_sentry_user_info())

        # Update extra data
        data.update(self.get_sentry_extra_info())

        return data
    
    def _capture(self, call_name, data=None, **kwargs):
        client = self.get_sentry_client()
        if not client:
            return
        
        if data is None:
            data = self.get_default_context()
        else:
            default_context = self.get_default_context()
            if isinstance(data, dict):
                default_context.update(data)
            else:
                default_context['extra']['extra_data'] = data
            data = default_context
            
        logger.debug('Sending to Sentry via method {}: {}'.format(call_name, data))

        return getattr(client, call_name)(data=data, **kwargs)

    def captureException(self, exc_info=None, **kwargs):
        return self._capture('captureException', exc_info=exc_info, **kwargs)

    def captureMessage(self, message, **kwargs):
        return self._capture('captureMessage', message=message, **kwargs)