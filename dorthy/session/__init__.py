from dorthy.settings import config

from .base import Session, InMemorySessionStore

session_store = None
if "web.session_store" in config:
    if config.web.session_store == "redis":
        from .redis import RedisSessionStore
        session_store = RedisSessionStore()
    elif config.web.session_store == "db":
        from .db import DBSessionStore
        session_store = DBSessionStore()

if session_store is None:
    session_store = InMemorySessionStore()
