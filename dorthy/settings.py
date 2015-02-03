import glob
import logging
import os
import yaml

logger = logging.getLogger(__name__)

config = None


class Properties(object):
    """Provides a property / attribute representation of a hierarchical
    dictionary of values"""

    def __init__(self, props):
        for name, value in props.items():
            if isinstance(value, dict):
                setattr(self, name, Properties(value))
            else:
                setattr(self, name, value)

    def __setattr__(self, name, value):
        if not hasattr(self, name):
            object.__setattr__(self, name, value)
        else:
            raise AttributeError("Cannot set values on properties objects")

    def __delattr__(self, name):
        raise AttributeError("Cannot delete values on properties objects")

    def __call__(self):
        """Calling an instance of a Property returns a dict representation
        of the property tree"""
        d = dict()
        for name, value in self.__dict__.items():
            if isinstance(value, Properties):
                d[name] = value()
            else:
                d[name] = value
        return d

    def __contains__(self, item):
        keys = item.split(".")
        prop_obj = self
        for key in keys:
            try:
                prop_obj = getattr(prop_obj, key)
            except AttributeError:
                return False
        return True

    def _asdict(self):
        return self.__call__()

    def enabled(self, key):
        try:
            return True if getattr(self, key) else False
        except AttributeError:
            return False

    def get(self, key, default=None, split=False):
        try:
            value = getattr(self, key)
        except AttributeError:
            return default
        else:
            if split:
                value = value.split(",")
                # remove the empty string from the end
                if not value[-1]:
                    value = value[:-1]
            return value


def _load_path(pathname):
    """Load yaml conf files for the given path into
    the module dictory configs"""
    props = {}
    path = os.path.join(pathname, "*.yml")
    for confpath in glob.iglob(path):
        with open(confpath) as f:
            key = os.path.basename(confpath)[:-4]
            conf = yaml.load(f)
            props[key] = conf

    global config
    if config is None:
        config = Properties(props)
    else:
        # reload config with overrides
        d = config._asdict()
        for name, value in props.items():
            d[name] = value
        config = Properties(d)


# load default path from working directory
_conf_dir = os.path.join(os.getcwd(), "conf")
_load_path(_conf_dir)

# load overrides
if os.getenv("CONF_OVERRIDE"):
    _load_path(os.path.join(_conf_dir, os.getenv("CONF_OVERRIDE")))