import hashlib
import os

from abc import ABCMeta, abstractmethod
from collections import namedtuple
from tempfile import NamedTemporaryFile

from tornado.gen import coroutine

from dorthy.background import runnable
from dorthy.web import consumes, MediaTypes, mediatype, BaseHandler

FileInfo = namedtuple("FileInfo",
                      ["name", "path", "content_type", "md5", "size"])

_upload_provides = dict()


class UploadProvider(metaclass=ABCMeta):
    """
    An abstract UploadProvier class. To use the UploadHandler
    you must implement this class and the two abstract methods.
    The name of your provider needs to match the provider_name in
    your call URI. All requests are processed async in a separate
    thread.
    """

    def __init__(self, handler):
        """
        Constructor that takes the handler that the provider is
        running under.

        :param handler: a RequestHandler
        :return: a newly constructed UploadProvider
        """
        self.handler = handler

    @classmethod
    @abstractmethod
    def get_name(cls):
        """
        The name used to register this provider.
        :return: a string that represents the name of the provider
        """
        pass

    @abstractmethod
    def process(self, file_info, data):
        """
        Abstract method that is called when the file is done uploading.

        :param file_info: the file info structure that describes the uploaded file
        :param data: an optional data object that is passed with the file.  This will
        be None if the file upload process does not pass a data object.

        :return: an object that will be serialized back to the client
        """
        pass

    @runnable
    def run(self, file_info, data):
        """
        The run method is called internally and should not be overridden.
        """
        self.process(file_info, data)


def create_provider(handler, provider_name):
    """
    Creates a new provider using the given provider_name

    :param handler: a RequestHandler
    :param provider_name: the name of the provider to create
    :return: a new UploadProvider
    """
    provider = _upload_provides.get(provider_name, None)
    if provider is None:
        raise ValueError("No provider found for upload: {}".format(provider_name))
    return provider(handler)


def register_provider(provider_cls):
    """
    Registers the given UploadProvider class with the upload framework.

    :param provider_cls: a sub-class of UploadProvider.  This should be a class
    and not an object.
    :raises ValueError if the provider is already registered
    """
    if provider_cls.get_name() in _upload_provides:
        raise ValueError("Provider is already registered: {}".format(provider_cls.get_name()))
    _upload_provides[provider_cls.get_name()] = provider_cls


class UploadHandler(BaseHandler):
    """
    Provides a generic upload handler that integrates with NGINX or can
    be used standalone.  The standalone version should only be used for test and
    development as it is not a scalable implementation.  The handler relies on
    UploadProviders to do the actual work.  An UploadProvider is run async once
    the file is available on disk. An optional JSON data structure can be passed as
    the form parameter 'data'.  This handler only supports single file uploads.

    To register the handler in tornado use a route like:

        (r"/upload/?(?P<provider_name>[\w_]+)", dorthy.upload.UploadHandler)

    NGINX server example:

        location ^~ /upload {

            upload_pass @tornado_upload;
            upload_store /tmp;

            # upload_store_access user:rw group:rw all:r;

            upload_set_form_field $upload_field_name.name "$upload_file_name";
            upload_set_form_field $upload_field_name.content_type "$upload_content_type";
            upload_set_form_field $upload_field_name.path "$upload_tmp_path";

            upload_aggregate_form_field "$upload_field_name.md5" "$upload_file_md5";
            upload_aggregate_form_field "$upload_field_name.size" "$upload_file_size";

            upload_pass_form_field "^data$";

            upload_cleanup 400-500;
        }

        location @tornado_upload {
            proxy_pass_header Server;
            proxy_set_header Host $http_host;
            proxy_redirect off;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Scheme $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_pass http://tornados;
        }

    This handler by default is not protected by the security system.  In order to
    require authentication override the prepare method:

        @authenticated(redirect=False)
        def prepare(self):
            super().prepare()
    """

    def _save_file(self):
        file_path = None
        try:
            req_file_info = self.request.files['file'][0]
            with NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(req_file_info["body"])
                file_path = temp_file.name

            stat_info = os.stat(file_path)
            file_size = stat_info.st_size
            md5hash = hashlib.md5(req_file_info["body"]).hexdigest()

            return FileInfo(name=req_file_info["filename"],
                            path=file_path,
                            content_type=req_file_info["content_type"],
                            md5=md5hash,
                            size=file_size)
        except:
            if file_path is not None:
                os.remove(file_path)
            raise

    @mediatype(MediaTypes.JSON)
    def prepare(self):
        self.set_nocache_headers()
        super().prepare()

    @coroutine
    @consumes(MediaTypes.JSON, arg_name="data", request_arg="data", optional_request_arg=True)
    def post(self, provider_name, data=None):
        file_name = self.get_argument("file.name", None)
        if file_name is None:
            # use internal tornado method to save file
            file_info = self._save_file()
        else:
            # file is processed by nginx externally
            file_info = FileInfo(name=file_name,
                                 path=self.get_argument("file.path"),
                                 content_type=self.get_argument("file.content_type"),
                                 md5=self.get_argument("file.md5"),
                                 size=self.get_argument("file.size"))

        try:
            provider = create_provider(self, provider_name)
            yield provider.run(file_info, data)
        finally:
            # remove temporary file
            os.remove(file_info.path)
