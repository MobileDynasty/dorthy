# Based on http://www.awebcoder.com/post/91001/extended-jsonify-function-for-appengine-s-db-model
import collections
import datetime
import inspect
import json
import logging
import sqlalchemy

from dorthy.utils import camel_encode, native_str

PRIMITIVE_TYPES = (bool, int, float, str)

logger = logging.getLogger(__name__)


def dumps(obj, basename, ancestors, camel_case=False, ignore_attributes=None, include_collections=None, encoding="utf-8"):
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
            return dumps(dict_attr(), basename, ancestors, camel_case, ignore_attributes, include_collections, encoding)
        else:
            raise ValueError("Invalid _as_dict attribute found on object")
    elif isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    elif isinstance(obj, dict) or isinstance(obj, collections.Mapping):
        if include_collections is None or _is_whitelisted_collection(basename, include_collections):
            values = {}
            for name, value in obj.items():
                name = native_str(name, encoding)
                new_basename = _append_path(basename, name)
                if camel_case:
                    name = camel_encode(name)
                if _is_blacklisted_attribute(new_basename, ignore_attributes) and not _is_whitelisted_collection(new_basename, include_collections):
                    continue
                new_ancestors = _set_ancestors(value, new_basename, ancestors, include_collections)
                values[name] = dumps(value, new_basename, new_ancestors, camel_case, ignore_attributes, include_collections, encoding)
            return values
        else:
            raise CollectionNotIncluded
    elif isinstance(obj, collections.Iterable):
        # blacklisting individual items causes problems.
        # easy to check blacklist for list.[2].attribute, but list.[*].attribute is expensive
        # since can't do a simple x in y test.
        # Block attributes of all list items by listname.attribute

        # we only use this for debugging. Doesn't propogate down, or it would interfere with
        # blacklist spec
        list_basename = _append_path(basename, 'list')
        # if a whitelist is specified, only iterate over this collection if it is in the list
        # blacklist works on the attribute name, so we won't get this far if this has been blacklisted
        if include_collections is None or _is_whitelisted_collection(basename, include_collections):
            vals = []
            for val in obj:
                new_ancestors = _set_ancestors(val, list_basename, ancestors, include_collections)
                # using basename instead of list_basename here on purpose. see above.
                vals.append(dumps(val, basename, new_ancestors, camel_case, ignore_attributes, include_collections, encoding))
            return vals
        else:
            raise CollectionNotIncluded

    # SQLAlchemy object handler
    try:
        inspection = sqlalchemy.inspect(obj)
        attrs = inspection.attrs.keys()
        transients = _get_transients(obj)
        relationships = inspection.mapper.relationships.keys()
        values = {}
        for attr in attrs:
            new_basename = _append_path(basename, attr)
            # Only serialize whitelisted relationships if include_collections is not None
            # This is slightly redundant as whitelist is checked for collections above, but checking here
            # prevents SQLAlchemy from running a lazy query on the object
            if _is_visible_attribute(attr, transients):  # transients and _ attrs can't be whitelisted
                if attr in relationships:
                    # allow whitelist to override blacklist on relationships
                    if _is_blacklisted_attribute(new_basename, ignore_attributes) and not _is_whitelisted_collection(new_basename, include_collections):
                        continue
                # if it's a plain attribute, just check against blacklist
                elif _is_blacklisted_attribute(new_basename, ignore_attributes):
                    continue
                value = getattr(obj, attr)
                if camel_case:
                    attr = camel_encode(attr)
                new_ancestors = _set_ancestors(value, new_basename, ancestors, include_collections)
                try:
                    values[attr] = dumps(value, new_basename, new_ancestors, camel_case, ignore_attributes, include_collections, encoding)
                except CollectionNotIncluded:
                    continue
        return values
    except sqlalchemy.exc.NoInspectionAvailable:
        pass

    # At this point, obj should be some sort of custom class instance

    values = {}
    transients = _get_transients(obj)
    serializable = dir(obj)

    for name in serializable:
        if _is_visible_attribute(name, transients):
            try:
                value = obj.__getattribute__(name)  # why not use getattr(obj, name) or even obj.name?
                new_basename = _append_path(basename, name)
                if _is_visible_type(value) and not _is_blacklisted_attribute(new_basename, ignore_attributes):
                    if camel_case:
                        name = camel_encode(name)
                    new_ancestors = _set_ancestors(value, new_basename, ancestors, include_collections)
                    values[name] = dumps(value, new_basename, new_ancestors, camel_case, ignore_attributes, include_collections, encoding)
            except AttributeError:
                continue
            except CollectionNotIncluded:
                continue
    if not values:
        return str(obj)
    else:
        return values


class CollectionNotIncluded(Exception):
    """Want to only apply the whitelist to collections. It's redundant to check the type of an attribute before
    calling dumps() on it. Raise this exception when processing a collection that is found on the whitelist.
    Catching this exception when assigning attr_name = dumps(collection) allows you to skip that attribute."""
    pass


def _set_ancestors(obj, basename, ancestors, include_collections):
    _ident = id(obj)
    # include_collections bypasses redundancy check
    if _ident in ancestors and not (include_collections is not None and basename in include_collections):
        raise ValueError("Circular reference detected: {} is parent {}".format(basename, ancestors[_ident]))
    else:
        new_ancestors = ancestors.copy()
        new_ancestors[_ident] = "." if basename == "" else basename

    return new_ancestors


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


def _is_visible_attribute(name, transients):
    return not(name.startswith("_") or
        name in transients)


def _is_whitelisted_collection(collection, include_collections):
    return include_collections is not None and collection in include_collections


def _is_blacklisted_attribute(attribute, ignore_attributes):
    return ignore_attributes is not None and attribute in ignore_attributes


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


class JSONEntityEncoder(json.JSONEncoder):

    def __init__(self, camel_case=False, ignore_attributes=None, encoding="utf-8", include_collections=None, **kwargs):
        super().__init__(**kwargs)
        self.__camel_case = camel_case
        self.__encoding = encoding
        self.__ignore_attributes = ignore_attributes
        self.__include_collections = include_collections

    def encode(self, obj):
        d = dumps(obj, "", {id(obj): '.'}, self.__camel_case, self.__ignore_attributes, self.__include_collections, self.__encoding, )
        en = super().encode(d)
        return en


def jsonify(obj, root=None, camel_case=False, ignore_attributes=None, sort_keys=True,
            indent=None, encoding="utf-8", include_collections=None, **kwargs):
    """
    JSONify the object provided
    """

    json_out = json.dumps(obj,
                          camel_case=camel_case,
                          ignore_attributes=ignore_attributes,
                          skipkeys=True,
                          sort_keys=sort_keys,
                          indent=indent,
                          cls=JSONEntityEncoder,
                          encoding=encoding,
                          include_collections=include_collections,
                          **kwargs)

    if root:
        return '{{"{!s}": {!s}}}'.format(root, json_out)
    else:
        return json_out
