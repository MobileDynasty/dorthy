import logging
import os

from concurrent.futures.process import ProcessPoolExecutor
from concurrent.futures.thread import ThreadPoolExecutor

from tornado.stack_context import StackContext

from dorthy.dp import Singleton
from dorthy.request import RequestContextManager
from dorthy.settings import config

from decorator import decorator

logger = logging.getLogger(__name__)

max_threads = config.background.max_threads if "background.max_threads" in config else (os.cpu_count() or 1) * 5
max_processes = config.background.max_processes if "background.max_processes" in config else os.cpu_count() or 1


@Singleton
class Executor(object):

    def get_executor(self, threaded=True):
        """
        Gets a executor to run background tasks

        :param threaded: True for a threaded executor, False for a process based executor
        :return: an Executor
        """
        if threaded:
            if not hasattr(self, "_thread_executor"):
                self._thread_executor = ThreadPoolExecutor(max_workers=max_threads)
            return self._thread_executor
        else:
            if not hasattr(self, "_process_executor"):
                self._process_executor = ProcessPoolExecutor(max_workers=max_processes)
            return self._process_executor


@decorator
def runnable(fn, *args, **kwargs):
    """
    Decorator to make a method into an asynchronous method run on a thread.
    Only supports threads do to a pickling problem with decorators across process
    boundaries.  In addition, it sets up a cloned RequestContext so that data can
    be shared across RequestContext boundaries.  The thread run within its own
    RequestContext boundary but has access to the data of the calling request.

        @runnable
        def foo():
            pass

    :return: a Future
    """

    # create a cloned copy of the existing RequestContext
    request_ctx = RequestContextManager.get_context().clone() if RequestContextManager.active() else None

    def execution_wrapper():
        # enable RequestContext on current thread
        with StackContext(RequestContextManager(request_ctx).context_manager):
            return fn(*args, **kwargs)

    return Executor().get_executor(threaded=True).submit(execution_wrapper)
