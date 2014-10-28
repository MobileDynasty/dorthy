from .base import BaseSessionStore, Session, DEFAULT_SESSION_TIMEOUT

from dorthy import redis
from dorthy.settings import config


WEB_SESSION_PREFIX = "web:session"


class RedisSessionStore(BaseSessionStore):

    @staticmethod
    def _store_key(session_id):
        return redis.create_key(WEB_SESSION_PREFIX, session_id)

    def load(self, session_id):
        session_data = redis.client.get(self._store_key(session_id))
        return self._validate_session(Session.decode(session_data)) if session_data else None

    def _delete(self, session_id):
        redis.client.delete(self._store_key(session_id))

    def _store_session(self, session):
        if session.valid:
            session._update_accessed()
            session_data = session.encode()
            timeout = config.web.session_timeout if session.timeout <= 0 else session.timeout
            if timeout <= 0:
                # always use a timeout with redis store to prevent orphan data
                timeout = DEFAULT_SESSION_TIMEOUT

            # timeout is not correct for non-updating sessions
            # will be caught by load method and expired check
            redis.client.setex(self._store_key(session.session_id),
                               timeout,
                               session_data)
        else:
            self._delete(session.session_id)