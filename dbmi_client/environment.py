import os
import json

import logging

logger = logging.getLogger(__name__)

__all__ = ["BASE_DIR", "absolute_path", "get_int", "get_bool", "get_str", "get_list", "get_dict"]

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def get_int(name, default=0, required=False):
    """
    Get a numeric value from environment and convert it accordingly.
    Return default if value does not exist or fails to parse.
    """
    if name not in os.environ:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be found")
        else:
            logger.error("ENV: Nothing found for: {}".format(name))
            return default

    try:
        value = os.environ.get(name, default)
        return int(value)
    except ValueError:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be parsed")
        else:
            logger.error("ENV: Non-numeric type found for: {}".format(name))
            return default


def absolute_path(*args):  # noqa
    return os.path.join(BASE_DIR, *args)


def get_bool(name, default=False, required=False):  # noqa
    """
    Get a boolean value from environment variable.
    If the environment variable is not set or value is not one or "true" or
    "false", the default value is returned instead.
    """

    if name not in os.environ:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be found")
        else:
            return default
    if os.environ[name].lower() in ["true", "yes", "1", "y"]:
        return True
    elif os.environ[name].lower() in ["false", "no", "0", "n"]:
        return False
    else:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be found")
        else:
            return default


def get_str(name, default=None, required=False):  # noqa
    """
    Get a string value from environment variable.
    If the environment variable is not set, the default value is returned
    instead.
    """

    value = os.environ.get(name, default)
    if value is None:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be found")
        else:
            logger.error("ENV: Nothing found for: {}".format(name))
            return default

    return value


def get_list(name, separator=",", default=None, required=False):  # noqa
    """
    Get a list of string values from environment variable.
    If the environment variable is not set, the default value is returned
    instead.
    """
    if name not in os.environ:
        if default is None:
            if required:
                raise SystemError(f"ENV: Required parameter {name} could not be found")
            else:
                logger.error("ENV: Nothing found for: {}".format(name))
                default = []
        return default
    return os.environ[name].split(separator)


def get_dict(name, default=None, required=False):
    """
    Get JSON encoded string from environment variable and return
    the default if it does not exist.
    """
    if name not in os.environ:
        if default is None:
            if required:
                raise SystemError(f"ENV: Required parameter {name} could not be found")
            else:
                logger.error("Nothing found for: {}".format(name))
                default = {}
        return default
    try:
        dict = json.loads(os.environ[name])
        return dict
    except ValueError:
        if required:
            raise SystemError(f"ENV: Required parameter {name} could not be found")
        else:
            logger.error("ENV: Failed to parse value for: {}".format(name))
            return default
