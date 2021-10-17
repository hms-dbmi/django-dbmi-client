import sys
import logging


def config(service, sentry=True, root_level=logging.WARNING):

    # Set the standard configurations
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "format": f"[DJANGO] - [{service.upper()}] - [%(asctime)s][%(levelname)s]"
                f"[%(name)s.%(funcName)s:%(lineno)d] - %(message)s",
            },
        },
        "handlers": {
            "console": {
                "level": "DEBUG",
                "class": "logging.StreamHandler",
                "formatter": "console",
                "stream": sys.stdout,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": logging.getLevelName(root_level),
        },
        "loggers": {
            "django": {
                "handlers": ["console"],
                "level": "WARNING",
                "propagate": True,
            },
            "django.request": {
                "handlers": ["console"],
                "level": "ERROR",
                "propagate": True,
            },
            'py.warnings': {
                'handlers': ['console'],
                'level': 'WARNING',
                'propagate': True
            },
        },
    }

    # Add Sentry/Raven
    if sentry:

        # Add the handler
        config["handlers"]["sentry"] = {
            "level": "ERROR",  # To capture more than ERROR, change to WARNING, INFO, etc.
            "class": "raven.contrib.django.raven_compat.handlers.SentryHandler",
            "tags": {"custom-tag": "x"},
        }
        config["root"]["handlers"].append("sentry")

        # Add the loggers
        config["loggers"]["raven"] = {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        }

        config["loggers"]["sentry.errors"] = {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        }

    return config


def add_level(levelName, levelNum, methodName=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
        raise AttributeError("{} already defined in logging module".format(levelName))
    if hasattr(logging, methodName):
        raise AttributeError("{} already defined in logging module".format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
        raise AttributeError("{} already defined in logger class".format(methodName))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)

    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)
