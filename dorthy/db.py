import logging

from contextlib import contextmanager
from datetime import datetime

from decorator import decorator

from sqlalchemy import orm, create_engine, BigInteger, Column, DateTime, Integer, event, exc, func, String
from sqlalchemy.pool import Pool
from sqlalchemy.orm.exc import NoResultFound, StaleDataError
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.ext.hybrid import Comparator
from sqlalchemy.types import TypeDecorator, SmallInteger

from dorthy.dp import Observable
from dorthy.enum import DeclarativeEnum
from dorthy.settings import config
from dorthy.request import RequestContextManager


logger = logging.getLogger(__name__)


class EntityBase(object):

    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

# Define Base class for ORM
Entity = declarative_base(cls=EntityBase)


class LookupMixin(object):

    native_code = Column(String(10), primary_key=True)
    friendly_name = Column(String(50), nullable=False)
    description = Column(String(1000), nullable=True)


class PrimaryKeyMixin(object):

    id = Column(BigInteger, primary_key=True)


class TimestampMixin(object):

    created = Column("created_ts", DateTime, nullable=False, default=datetime.today)


class UpdateTimestampMixin(TimestampMixin):

    updated = Column("updated_ts", DateTime)


class VersionedMixin(object):

    version_id = Column(Integer, nullable=False)

    __mapper_args__ = {
        "version_id_col": version_id
    }


class EnumIntType(TypeDecorator):

    impl = SmallInteger

    def __init__(self, values=None):
        super().__init__(self)
        self.values = values

    def process_bind_param(self, value, dialect):
        return None if value is None else self.values.index(value)

    def process_result_value(self, value, dialect):
        return None if value is None else self.values[value]


def get_enum_values(type_name):
    result = Session().execute("SELECT e.enumlabel " +
                               "FROM pg_enum e " +
                               "JOIN pg_type t ON e.enumtypid = t.oid " +
                               "WHERE t.typname=:typename", {"typename": type_name}).fetchall()
    return [row[0] for row in result]


class TransactionScope(DeclarativeEnum):
    Required = "required"


@contextmanager
def transacted_session(**kwargs):

    session = Session()
    # currently only support new tx and joining existing
    session.begin(subtransactions=True, **kwargs)
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    else:
        session.commit()


def transactional(scope=TransactionScope.Required):
    def _transactional(f, *args, **kwargs):
        with transacted_session():
            return f(*args, **kwargs)
    return decorator(_transactional)


@transactional()
def add(entity):
    Session().add(entity)
    return entity


def find_by_id(entity_type, entity_id, not_found_error=True):
    try:
        return Session().query(entity_type).\
            filter(entity_type.id == entity_id).one()
    except NoResultFound:
        if not_found_error:
            raise
        return None


def find_by_id_versioned(entity_type, entity_id, version_id):
    try:
        return Session().query(entity_type).\
            filter(entity_type.id == entity_id).\
            filter(entity_type.version_id == version_id).one()
    except NoResultFound:
        raise StaleDataError("Entity not found for version - id: {}, version: {}".format(entity_id, version_id))


def find_all(entity_type):
    return Session().query(entity_type).all()


@transactional()
def delete(entity_type, entity_id):
    entity = find_by_id(entity_type, entity_id)
    Session().delete(entity)


@transactional()
def delete_versioned(entity_type, entity_id, version_id):
    entity = find_by_id_versioned(entity_type, entity_id, version_id)
    Session().delete(entity)


class CaseInsensitiveComparator(Comparator):

    def __eq__(self, other):
        return func.lower(self.__clause_element__()) == func.lower(other)


def _create_engine():
    # define DB Engine
    db_conf = config.db

    host = db_conf.host
    name = db_conf.name
    port = db_conf.port
    db_url = "postgresql://{user}:{password}@{host}:{port}/{db}".format(
        user=db_conf.username,
        password=db_conf.password,
        host=host,
        port=port,
        db=name)

    return create_engine(db_url,
                         pool_recycle=900,
                         echo="debug" if db_conf.enabled("debug") else False,
                         isolation_level="READ COMMITTED")


def _create_scoped_session(scope_func=None):
    # autocommit true is used for begin / commit functionality in
    # transactional decorators -- subtransaction support
    # http://docs.sqlalchemy.org/en/rel_0_7/orm/session.html#session-subtransactions
    return orm.scoped_session(orm.sessionmaker(bind=_create_engine(), autocommit=True), scope_func)


class SessionContext(object):

    def __init__(self):
        self.__request_context_scope = \
            _create_scoped_session(scope_func=SessionContext._request_context_scope_func)
        self.__thread_local_scope = \
            _create_scoped_session()
        self.__observable = Observable()

    def __call__(self, *args, **kwargs):
        if self.request_context_scoped:
            session = self.__request_context_scope()
        else:
            session = self.__thread_local_scope()
        return self._init_session(session)

    @property
    def request_context_scoped(self):
        return RequestContextManager.active()

    def remove(self):
        if self.request_context_scoped:
            self.__request_context_scope.remove()
        else:
            self.__thread_local_scope.remove()

        # call listeners on removed event
        self.__observable("removed", None)

    def _init_session(self, session):

        # add register after commit method to the session
        if not hasattr(session, "register_after_commit"):
            session.after_commit_callbacks = []
            session.register_after_commit = lambda cb, handle_error=False: \
                session.after_commit_callbacks.append((cb, handle_error))

        # call listeners on created event
        self.__observable("created", session)

        return session

    @staticmethod
    def _request_context_scope_func():
        request_context = RequestContextManager.get_context()
        if not request_context.contains_listener(SessionContext._request_context_session_release):
            request_context.register_listener(SessionContext._request_context_session_release)
        return request_context.id

    @staticmethod
    def _request_context_session_release(event, context):
        # remove sessions on deactivate events
        if event == "deactivate":
            try:
                Session.remove()
            except:
                logger.warn("Failed to remove db session from request context: %s", context.id)

    def contains_listener(self, listener):
        return listener in self.__observable

    def register_listener(self, listener):
        self.__observable.register(listener)


# Global session for the application
# Sessions are scoped - request or thread local
Session = SessionContext()


#
# Configure Event Listeners
#
def update_timestamp(mapper, connection, target):
    target.updated = datetime.today()


def validator(mapper, connection, target):
    if hasattr(target, "validate"):
        target.validate()


@event.listens_for(orm.mapper, "mapper_configured")
def set_events(mapper, cls):
    if issubclass(cls, UpdateTimestampMixin):
        event.listen(cls, "before_update", update_timestamp)
    if hasattr(cls, "validate"):
        event.listen(cls, "before_update", validator)
        event.listen(cls, "before_insert", validator)


@event.listens_for(Pool, "checkout")
def ping_connection(dbapi_connection, connection_record, connection_proxy):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("SELECT 1")
    except:
        # optional - dispose the whole pool
        # instead of invalidating one at a time
        # connection_proxy._pool.dispose()

        # raise DisconnectionError - pool will try
        # connecting again up to three times before raising.
        raise exc.DisconnectionError()
    else:
        cursor.close()


@event.listens_for(orm.Session, "after_commit")
def exec_commit_callbacks(session):
    if hasattr(session, "after_commit_callbacks") and session.after_commit_callbacks:
        try:
            for cb in session.after_commit_callbacks:
                try:
                    cb[0]()
                except:
                    if not cb[1]:
                        raise
                    logger.exception("Failed to process after commit callback.")
        finally:
            session.after_commit_callbacks[:] = []