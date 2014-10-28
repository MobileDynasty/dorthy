import logging

from dorthy.settings import config

from .base import Session, InMemorySessionStore

logger = logging.getLogger(__name__)

session_store = None
if "web.session_store" in config:
    if config.web.session_store == "redis":
        from .redis import RedisSessionStore
        session_store = RedisSessionStore()
        logger.info("Using Session Store: redis")
    elif config.web.session_store == "db":
        from .db import DBSessionStore
        session_store = DBSessionStore()
        logger.info("Using Session Store: db")

if session_store is None:
    session_store = InMemorySessionStore()
    logger.info("Using Session Store: in-memory")
