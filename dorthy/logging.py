import os
import logging.handlers


class EnvRotatingFileHandler(logging.handlers.RotatingFileHandler):

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None, **kwargs):
        filename = filename.format(**os.environ)
        super().__init__(filename, mode, maxBytes, backupCount, encoding, **kwargs)
