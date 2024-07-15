from __future__ import absolute_import, unicode_literals

import os
import warnings
import logging

from django.conf import settings
from django.test.signals import setting_changed

from dbmi_client import environment as env

# Always import this module as follows:
# from dbmi_client import settings [as dbmi_settings]

# Don't import directly CONFIG or PANELs, or you will miss changes performed
# with override_settings in tests.

# Set service URLs based on environment
DBMI_ENVIRONMENTS = {
    "prod": {
        "AUTHN_URL": "https://authentication.dbmi.hms.harvard.edu",
        "AUTHZ_URL": "https://authorization.dbmi.hms.harvard.edu",
        "REG_URL": "https://registration.dbmi.hms.harvard.edu",
        "FILESERVICE_URL": "https://files.dbmi.hms.harvard.edu",
        "JWT_AUTHZ_NAMESPACE": "https://authorization.dbmi.hms.harvard.edu",
    },
    "dev": {
        "AUTHN_URL": "https://authentication.aws.dbmi-dev.hms.harvard.edu",
        "AUTHZ_URL": "https://authorization.aws.dbmi-dev.hms.harvard.edu",
        "REG_URL": "https://registration.aws.dbmi-dev.hms.harvard.edu",
        "FILESERVICE_URL": "https://fileservice.aws.dbmi-dev.hms.harvard.edu",
        "JWT_AUTHZ_NAMESPACE": "https://authorization.aws.dbmi-dev.hms.harvard.edu",
    },
}

CONFIG_DEFAULTS = {
    # The identifier for this service and/or project
    "CLIENT": None,
    # Client options, assume production environment
    "ENVIRONMENT": "prod",
    # Set prod URLs
    "AUTHN_URL": None,
    "AUTHZ_URL": None,
    "REG_URL": None,
    "FILESERVICE_URL": None,
    # Optionally disable logging
    "LOGGER_NAME": "dbmi_client",
    "ENABLE_LOGGING": True,
    "LOG_LEVEL": logging.WARNING,
    # Universal login screen branding
    "AUTHN_TITLE": "DBMI Client",
    "AUTHN_ICON_URL": "https://authentication.dbmi.hms.harvard.edu/static/hms_logo.svg",
    "AUTHN_COLOR": "#bc262b",
    "AUTHN_BACKGROUND": None,
    # AuthZ groups/roles/permissions
    "AUTHZ_ADMIN_GROUP": "dbmi-admin",
    "AUTHZ_ADMIN_PERMISSION": "MANAGE",
    "AUTHZ_USER_GROUP": "dbmi-user",
    "AUTHZ_REPORTER_CLASS": "dbmi_client.authz.AuthorizationReporter",
    # JWT bits
    "JWT_AUTHZ_NAMESPACE": None,
    "JWT_HTTP_PREFIX": "JWT ",
    "JWT_COOKIE_NAME": "DBMI_JWT",
    "JWT_COOKIE_DOMAIN": ".dbmi.hms.harvard.edu",
    # Authentication provider details
    "AUTH_CLIENTS": None,
    "AUTH_ENCRYPTION_KEYS": [],
    # Configurations surrounding usage of a local Django user model
    "USER_MODEL_ENABLED": False,
    "USER_MODEL_AUTOCREATE": True,
    # These configurations are specific to DRF related auth/permissions
    "DRF_OBJECT_OWNER_KEY": "user",
    # Jira support desk properties
    "JIRA_ORGANIZATION": "hms-dbmi",
    "JIRA_SERVICE_DESK": None,
    "JIRA_SERVICE_DESK_EMAIL": None,
    "JIRA_USERNAME": None,
    "JIRA_TOKEN": None,
    # Filservice
    "FILESERVICE_TOKEN": None,  # The authentication token to be used with Fileservice
    "FILESERVICE_BUCKETS": [],  # The name of the S3 buckets Fileservice should use
    "FILESERVICE_GROUP": None,  # Typically would be the same as CLIENT
    "FILESERVICE_ADMINS": [],  # A list of Fileservice users and/or user emails that should administer group
    # Login settings
    "LOGIN_REDIRECT_KEY": "next",  # The query parameter key specifying where logged in users should be sent
    "LOGIN_REDIRECT_URL": None,  # The post-login URL to send users to if not specified by 'LOGIN_REDIRECT_KEY'
    # Logout settings
    "LOGOUT_REDIRECT_KEY": "next",  # The query parameter key specifying where logged out users should be sent
    "LOGOUT_REDIRECT_URL": None,  # The post-logout URL to send users to if not specified by 'LOGOUT_REDIRECT_KEY'
}

# List of settings that cannot be defaulted and must be user-defined
REQUIRED_SETTINGS = ("CLIENT", "AUTH_CLIENTS", )

# List of settings that have been removed
REMOVED_SETTINGS = (
    "AUTH0_TENANT", "AUTH0_CLIENT_ID", "AUTH0_SECRET", "AUTH0_CLIENTS", "AUTH0_TENANTS", "AUTH0_SCOPE", "AUTH0_DOMAIN"
)


class DBMISettings(object):
    """
    A settings object, that allows DBMI Client settings to be accessed as properties.
    For example:
        from dbmi_client.settings import dbmi_settings
        print(dbmi_settings.AUTHZ_ADMIN_GROUP)
    Any setting with string import paths will be automatically resolved
    and return the class, rather than the string literal.
    """

    def __init__(self, defaults=None):
        self.defaults = defaults or CONFIG_DEFAULTS
        self._cached_attrs = set()

    @property
    def user_settings(self):

        # Check to see if user configs have been loaded or not
        if not hasattr(self, "_user_settings"):

            try:
                # Load user-specified configurations
                user_settings = getattr(settings, "DBMI_CLIENT_CONFIG", {})

                # Update the client config with pre-defined environment URLs, etc
                if user_settings.get("ENVIRONMENT") in DBMI_ENVIRONMENTS:
                    env_settings = DBMI_ENVIRONMENTS[user_settings.get("ENVIRONMENT")]
                    user_settings.update({k: v for k, v in env_settings.items() if k not in user_settings})

                else:
                    # Check for them in environment
                    for key in DBMI_ENVIRONMENTS["prod"].keys():
                        if env.get_str("DBMI_{}".format(key.upper())):
                            user_settings[key] = env.get_str("DBMI_{}".format(key.upper()))

                # Check them
                self._user_settings = self.__check_user_settings(user_settings)

            except Exception as e:
                raise SystemError("DBMI Client settings are invalid: {}".format(e))

        return self._user_settings

    def __getattr__(self, attr):

        # Any attribute must be in either required settings or defaults
        if attr not in REQUIRED_SETTINGS and attr not in self.defaults:
            raise AttributeError("Invalid DBMI setting: '%s'" % attr)

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:

            # Fall back to defaults
            val = self.defaults[attr]

        # Cache the result
        self._cached_attrs.add(attr)
        setattr(self, attr, val)

        return val

    def __check_user_settings(self, user_settings):
        SETTINGS_DOC = "https://github.com/hms-dbmi/django-dbmi-client"

        for setting in REMOVED_SETTINGS:
            if setting in user_settings:
                raise RuntimeError(
                    "The '%s' setting has been removed. Please refer to '%s' for available settings."
                    % (setting, SETTINGS_DOC)
                )

        if "CLIENT" not in user_settings:
            raise AttributeError("CLIENT configuration must be set")

        # Check auth configuration(s)
        if type(user_settings["AUTH_CLIENTS"]) is not dict:
            raise AttributeError("AUTH_CLIENTS configuration must be set as a dictionary")

        # Check each auth configuration
        for _, configuration in user_settings["AUTH_CLIENTS"].items():

            # Each client needs a minimum of a JWKS URL
            if not configuration.get("JWKS_URL") and not configuration.get("CLIENT_SECRET"):
                raise AttributeError("Each auth client required a configured JWKS_URL or CLIENT_SECRET")

            # If the login app is enabled, more is required for each client
            if "dbmi_client.login" in settings.INSTALLED_APPS:

                # Check secret
                if not configuration.get("PROVIDER"):
                    raise AttributeError("Each auth client required a configured PROVIDER: 'auth0' or 'cognito'")

                # Check secret
                if not configuration.get("CLIENT_SECRET"):
                    raise AttributeError("Each auth client required a configured CLIENT_SECRET")

                # Check secret
                if not configuration.get("DOMAIN"):
                    raise AttributeError("Each auth client required a configured DOMAIN")

                # Check secret
                if not configuration.get("SCOPE"):
                    raise AttributeError("Each auth client required a configured SCOPE")

        # Ensure environment is set and if not prod or dev, ensure service URLs are provided
        if (
            "ENVIRONMENT" in user_settings
            and user_settings["ENVIRONMENT"].lower() != "prod"
            and user_settings["ENVIRONMENT"].lower() != "dev"
        ):
            warnings.warn("ENVIRONMENT is not set to production, this should be a test environment", ResourceWarning)

            missing_urls = []
            if "AUTHN_URL" not in user_settings:
                # Check environment
                if os.environ.get("DBMI_AUTHN_URL"):
                    user_settings["AUTHN_URL"] = os.environ.get("DBMI_AUTHN_URL")
                else:
                    missing_urls.append("AUTHN_URL")

            if "AUTHZ_URL" not in user_settings:
                # Check environment
                if os.environ.get("DBMI_AUTHZ_URL"):
                    user_settings["AUTHZ_URL"] = os.environ.get("DBMI_AUTHZ_URL")
                else:
                    missing_urls.append("AUTHZ_URL")

            if "REG_URL" not in user_settings:
                # Check environment
                if os.environ.get("DBMI_REG_URL"):
                    user_settings["REG_URL"] = os.environ.get("DBMI_REG_URL")
                else:
                    missing_urls.append("REG_URL")
            if missing_urls:
                raise AttributeError("{} configuration(s) must be set".format(missing_urls))

            if "FILESERVICE_URL" not in user_settings:
                # Check environment
                if os.environ.get("DBMI_FILESERVICE_URL"):
                    user_settings["FILESERVICE_URL"] = os.environ.get("DBMI_FILESERVICE_URL")
                else:
                    warnings.warn("FILESERVICE_URL is not set, Fileservice requests will fail", ResourceWarning)

            if (
                "FILESERVICE_GROUP" in user_settings
                or "FILESERVICE_BUCKETS" in user_settings
                or "FILESERVICE_ADMINS" in user_settings
                or "FILESERVICE_TOKEN" in user_settings
            ) and (
                "FILESERVICE_GROUP" not in user_settings
                or "FILESERVICE_BUCKETS" not in user_settings
                or "FILESERVICE_ADMINS" not in user_settings
                or "FILESERVICE_TOKEN" not in user_settings
            ):
                warnings.warn(
                    "FILESERVICE_GROUP, FILESERVICE_BUCKETS, FILESERVICE_ADMINS and FILESERVICE_TOKEN must be "
                    "defined for Fileservice usage",
                    ResourceWarning,
                )

            if "JWT_AUTHZ_NAMESPACE" not in user_settings:
                warnings.warn(
                    "JWT_AUTHZ_NAMESPACE is not set, JWT claims will not be inspected " "for groups/roles/permissions",
                    ResourceWarning,
                )

        if "JWT_HTTP_PREFIX" in user_settings:
            warnings.warn("Changing JWT_HTTP_PREFIX breaks compatibility with DBMI services", ResourceWarning)

        if "JWT_COOKIE_NAME" in user_settings:
            warnings.warn("Changing JWT_COOKIE_NAME breaks compatibility with DBMI services", ResourceWarning)

        return user_settings

    def reload(self):
        for attr in self._cached_attrs:
            delattr(self, attr)
        self._cached_attrs.clear()
        if hasattr(self, "_user_settings"):
            delattr(self, "_user_settings")

    def __dir__(self):

        # Return defaults and user configs patched over
        attrs = dict()
        attrs.update(self.defaults)
        attrs.update(self.user_settings)

        return attrs.keys()

    @property
    def USER_MODEL_ENABLED(self):

        try:
            # Check if present in user settings
            return self.user_settings["USER_MODEL_ENABLED"]

        except KeyError:

            # Else, return true if the client has added either backend classes to AUTHENTICATION_BACKENDS
            return (
                "dbmi_client.authn.DBMIModelAuthenticationBackend" in settings.AUTHENTICATION_BACKENDS
                or "dbmi_client.authn.DBMIUsersModelAuthenticationBackend" in settings.AUTHENTICATION_BACKENDS
                or "dbmi_client.authn.DBMIAdminModelAuthenticationBackend" in settings.AUTHENTICATION_BACKENDS
            )

    def get_logger(self):
        """
        Returns the logger and manages whether logs propogate or not depending on user configs
        :return: logger
        """
        logger = logging.getLogger(__name__)

        # Check if disabled
        if not self.ENABLE_LOGGING:
            logger.propagate = False

        return logger


# Create the instance by which the settings should be accessed
dbmi_settings = DBMISettings(CONFIG_DEFAULTS)

# Configure logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)
logger.disabled = not dbmi_settings.ENABLE_LOGGING
logger.setLevel(dbmi_settings.LOG_LEVEL)


def reload_dbmi_settings(*args, **kwargs):
    setting = kwargs["setting"]
    if setting == "DBMI_CLIENT_CONFIG":
        dbmi_settings.reload()


setting_changed.connect(reload_dbmi_settings)
