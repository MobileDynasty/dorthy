"""Enum implementation originally from zzzeek:
http://techspot.zzzeek.org/2011/01/14/the-enum-recipe/

Our db enum type does not use sqlalchemy's built-in enum type
instead we just use a string.  We do not have consistency checks
within the database.
"""

from sqlalchemy.types import SchemaType, TypeDecorator, Integer, String


class EnumSymbol(object):
    """Define a fixed symbol tied to a parent class."""

    def __init__(self, cls_, name, value, description=None):
        self.cls_ = cls_
        self.__name = name
        self.__value = value
        self.__description = description

    def __eq__(self, other):
        return id(self) == id(other)

    def __hash__(self):
        return id(self)

    def __reduce__(self):
        """Allow unpickling to return the symbol
        linked to the DeclarativeEnum class."""
        return getattr, (self.cls_, self.name)

    def __iter__(self):
        return iter([self.value, self.description])

    def __repr__(self):
        if self.__description:
            return "<{}, {}, {}>".format(self.name, self.value, self.description)
        else:
            return "<{}, {}>".format(self.name, self.value)

    def __str__(self):
        return str(self.__value)

    def _as_dict(self):
        return {
            "name": self.name,
            "value": self.value,
            "description": self.description
        }

    @property
    def name(self):
        return self.__name

    @property
    def value(self):
        return self.__value

    @property
    def description(self):
        return self.__description


class EnumMeta(type):
    """Generate new DeclarativeEnum class.

    Only supports int and string type as values of the enum
    """

    def __init__(cls, classname, bases, dict_):

        cls._registered = registered = cls._registered.copy()

        for k, v in dict_.items():

            if k[0] == "_":
                continue

            value = description = None
            if isinstance(v, tuple) and len(v) > 0:
                assert isinstance(v[0], str) or isinstance(v[0], int), \
                    "Declarative Enum only supports string and ints as values."
                value = v[0]
                # if defined as a tuple w/o description use the key
                description = v[1] if len(v) > 1 else k
            elif isinstance(v, str) or isinstance(v, int):
                value = v

            if value is not None:
                if cls.int_enum() and not isinstance(value, int):
                    raise ValueError("Enum can only contain integer values.")

                # normalize all keys to strings
                value_str = str(value)
                if value_str in registered:
                    raise ValueError("Declarative Enum only supports unique values.")

                sym = registered[value_str] = EnumSymbol(cls, k, value, description=description)
                setattr(cls, k, sym)

        type.__init__(cls, classname, bases, dict_)


class DeclarativeEnum(metaclass=EnumMeta):
    """Declarative enumeration that will except
    String and int values"""

    _registered = dict()

    @classmethod
    def convert(cls, value):
        """
        Converts the given value to the enum value

        Returns:
            the enum for the given value
        Raises:
            ValueError: the enum value does not exist in the enum
        """
        # convert non-string values
        value = str(value)
        try:
            return cls._registered[value]
        except KeyError:
            raise ValueError("Invalid value for {}: {}".format(cls.__name__, value))

    @classmethod
    def values(cls):
        """
        Returns all the EnumSymbol values for the given enum.

        Returns:
            all EnumSymbol values for the given enum
        """
        return cls._registered.values()

    @classmethod
    def keys(cls):
        """
        Returns all the keys for the given enum.

        Returns:
            all EnumSymbol keys for the given enum
        """
        return cls._registered.keys()

    @classmethod
    def int_enum(cls):
        return False

    @classmethod
    def db_type(cls):
        """
        Generates the SQLAlchemy DB type for the given enum

        Returns:
            a DeclarativeEnumType for the enum
        """
        return DeclarativeEnumType(cls)


class IntDeclarativeEnum(DeclarativeEnum):
    """A declarative enumeration with that will
    only except int values.
    """

    # needed to differentiate the class because the definition of the class
    # is not available to the meta class when DeclarativeEnum is first called
    @classmethod
    def int_enum(cls):
        return True


class DeclarativeEnumType(SchemaType, TypeDecorator):
    """SQLAlchemy DeclarativeEnum type

    This implementation either stores all enum values as strings in the DB
    or can be configured to store values as integers.
    """

    def __init__(self, enum):
        super().__init__()
        if enum.int_enum():
            self.impl = Integer()
        else:
            for v in enum.values():
                v_str = str(v.value)
                if len(v_str) > 10:
                    raise ValueError("Enum keys cannot be greater than 10 characters. Enum: {} Key: {}".
                                     format(enum.__name__, v_str))
            self.impl = String(length=10)

        self.enum = enum

    def copy(self, **kwargs):
        return DeclarativeEnumType(self.enum)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if self.enum.int_enum():
            return value.value
        else:
            return str(value.value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if not self.enum.int_enum():
            value = value.strip()
        return self.enum.convert(value)

    def __repr__(self):
        """Defined to override default behavior for alembic generation
        see: https://bitbucket.org/zzzeek/alembic/issue/78/autogenerate-does-not-detect-decorated
        """
        if self.enum.int_enum():
            return "Integer"
        else:
            return "String(length=10)"
