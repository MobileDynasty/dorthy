# Based on http://www.awebcoder.com/post/91001/extended-jsonify-function-for-appengine-s-db-model
import collections
import datetime
import inspect
import json
import logging

from dorthy.utils import camel_encode, native_str

PRIMITIVE_TYPES = (bool, int, float, str)

logger = logging.getLogger(__name__)


def dumps(obj, basename, camel_case=False, ignore_attributes=None, encoding="utf-8"):
    """
    Provides basic json encoding.  Handles encoding of SQLAlchemy objects
    """

    if obj is None:
        return None
    elif isinstance(obj, PRIMITIVE_TYPES):
        return obj
    elif isinstance(obj, bytes):
        return native_str(obj, encoding)
    elif hasattr(obj, "_json"):
        json_obj = getattr(obj, "_json")
        if callable(json_obj):
            return json_obj()
        elif isinstance(json_obj, str):
            return json_obj
        else:
            raise ValueError("Invalid _json attribute found on object")
    elif hasattr(obj, "_as_dict"):
        dict_attr = getattr(obj, "_as_dict")
        if callable(dict_attr):
            return dumps(dict_attr(), basename, camel_case, ignore_attributes, encoding)
        else:
            raise ValueError("Invalid _as_dict attribute found on object")
    elif isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    elif isinstance(obj, dict) or isinstance(obj, collections.Mapping):
        values = dict()
        for name, value in obj.items():
            name = native_str(name, encoding)
            new_basename = _append_path(basename, name)
            if camel_case:
                name = camel_encode(name)
            if not ignore_attributes or new_basename not in ignore_attributes:
                values[name] = dumps(value, new_basename, camel_case, ignore_attributes, encoding)
        return values
    elif isinstance(obj, collections.Iterable):
        return [dumps(val, basename, camel_case, ignore_attributes, encoding) for val in obj]

    values = dict()
    transients = _get_transients(obj)
    serializable = dir(obj)

    for name in serializable:
        if _is_visible_attribute(obj, name, transients):
            try:
                value = obj.__getattribute__(name)
                new_basename = _append_path(basename, name)
                if _is_visible_type(value) and (not ignore_attributes or new_basename not in ignore_attributes):
                    if camel_case:
                        name = camel_encode(name)
                    values[name] = dumps(value, new_basename, camel_case, ignore_attributes, encoding)
            except Exception:
                continue
    if not values:
        return str(obj)
    else:
        return values


def _get_transients(obj):
    transients = set()
    trans_attr = getattr(obj, "_transients", None)
    if trans_attr:
        if callable(trans_attr):
            trans = trans_attr()
        else:
            trans = trans_attr

        if trans:
            if isinstance(trans, str):
                transients.add(trans)
            elif isinstance(trans, collections.Iterable):
                transients.update(trans)
    return transients


def _append_path(basename, name):
    if basename:
        return native_str(basename + '.' + name)
    else:
        return native_str(name)


def _is_visible_attribute(obj, name, transients):
    return not(name.startswith("_") or
        name in transients or
        (_is_saobject(obj) and name == "metadata"))


def _is_visible_type(attribute):
    return not(inspect.isfunction(attribute) or
               inspect.ismethod(attribute) or
               inspect.isbuiltin(attribute) or
               inspect.isroutine(attribute) or
               inspect.isclass(attribute) or
               inspect.ismodule(attribute) or
               inspect.istraceback(attribute) or
               inspect.isframe(attribute) or
               inspect.iscode(attribute) or
               inspect.isabstract(attribute) or
               inspect.ismethoddescriptor(attribute) or
               inspect.isdatadescriptor(attribute) or
               inspect.isgetsetdescriptor(attribute) or
               inspect.ismemberdescriptor(attribute))


def _is_saobject(obj):
    return hasattr(obj, "_sa_class_manager")


class JSONEntityEncoder(json.JSONEncoder):

    def __init__(self, camel_case=False, ignore_attributes=None, encoding="utf-8", **kwargs):
        super().__init__(**kwargs)
        self.__camel_case = camel_case
        self.__encoding = encoding
        self.__ignore_attributes = ignore_attributes

    def encode(self, obj):
        d = dumps(obj, "", self.__camel_case, self.__ignore_attributes, self.__encoding)
        en = super().encode(d)
        return en


def jsonify(obj, root=None, camel_case=False, ignore_attributes=None, sort_keys=True,
            indent=None, encoding="utf-8", **kwargs):
    """
    JSONify the object provided
    """
    # add root to the base of ignore_attributes
    if root:
        if ignore_attributes:
            ignore_attributes = ["{}.{}".format(root, val) for val in ignore_attributes]
        obj = {root: obj}
    return json.dumps(obj,
                      camel_case=camel_case,
                      ignore_attributes=ignore_attributes,
                      skipkeys=True,
                      sort_keys=sort_keys,
                      indent=indent,
                      cls=JSONEntityEncoder,
                      encoding=encoding,
                      **kwargs)
