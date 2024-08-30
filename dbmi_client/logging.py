import sys
import logging
from typing import Optional


# Create a filter to hide Sentry metrics transactions
class SentryIngestFilter(logging.Filter):
    def filter(self, record):
        # Sentry makes a POST to this URL every minute (although configurable)
        # so hide these messages since we still want to see POST records
        # from other libraries
        return "ingest.us.sentry.io" not in record.getMessage()


def config(service: str, root_level: int = logging.WARNING, logger_levels: Optional[dict[str, str]] = None) -> dict:
    """
    Configures logging for the current application

    :param service: The name of the service to prefix logs with
    :type service: str
    :param root_level: The root logging level to set, defaults to logging.WARNING
    :type root_level: int, optional
    :param logger_levels: A mapping of loggers to the log level to be used for them, defaults to None
    :type logger_levels: Optional[dict[str, str]], optional
    :return: The logging configuration as a dict
    :rtype: dict
    """
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
                "filters": [
                    "sentryIngestFilter",
                ]
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
        "filters": {
            "sentryIngestFilter": {
                "()": "dbmi_client.logging.SentryIngestFilter"
            }
        }
    }

    # Check for additional logger level configurations
    if logger_levels:

        config["loggers"].update({
            k: {
                'handlers': ['console'],
                'level': v,
                'propagate': True
            } for k, v in logger_levels.items()
        })

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
