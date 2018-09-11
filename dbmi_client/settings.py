from __future__ import absolute_import, unicode_literals

import warnings

from django.conf import settings

# Always import this module as follows:
# from dbmi_client import settings [as dbmi_settings]

# Don't import directly CONFIG or PANELs, or you will miss changes performed
# with override_settings in tests.

CONFIG_DEFAULTS = {
    # Client options, assume production environment
    'ENVIRONMENT': 'production',
    'AUTHN_URL': 'https://authentication.dbmi.hms.harvard.edu/',
    'AUTHZ_URL': 'https://authorization.dbmi.hms.harvard.edu/',
    'REG_URL': 'https://registration.dbmi.hms.harvard.edu/',
    'AUTHZ_ADMIN_GROUP': 'dbmi-admin',
    'AUTHZ_USER_GROUP': 'dbmi-user',
    'JWT_AUTHZ_NAMESPACE': 'https://authorization.dbmi.hms.harvard.edu',
    'JWT_HTTP_PREFIX': 'JWT ',
    'JWT_COOKIE_NAME': 'DBMI_JWT',
    'JWT_COOKIE_DOMAIN': '.dbmi.hms.harvard.edu',
    'AUTHN_LOGO_URL': 'https://authentication.dbmi.hms.harvard.edu/static/hms_shield.png',
    'AUTH0': {
        'CLIENT_IDS': ['!!! must be configured by client !!!'],
        'DOMAIN': 'dbmiauth.auth0.com',
    },
    'AUTHN_BRANDING': {
        'TITLE': 'DBMI Client',
        'ICON_URL': 'https://authentication.dbmi.hms.harvard.edu/static/hms_shield.png',
    }
}

CLIENT_CONFIG = getattr(settings, 'DBMI_CLIENT_CONFIG', {})

if 'CLIENT' not in CLIENT_CONFIG:
    raise AttributeError('CLIENT configuration must be set')

if 'AUTH0' not in CLIENT_CONFIG:
    raise AttributeError('AUTH0 configuration must be set')

if 'CLIENT_IDS' not in CLIENT_CONFIG['AUTH0']:
    raise AttributeError('AUTH0.CLIENT_IDS configuration must be set')

if 'DOMAIN' not in CLIENT_CONFIG['AUTH0']:
    raise AttributeError('AUTH0.DOMAIN configuration must be set')

if 'ENVIRONMENT' in CLIENT_CONFIG and CLIENT_CONFIG['environment'] != 'production':
    warnings.warn(
        "ENVIRONMENT is not set to production, this should be a test or dev environment", ResourceWarning)

if 'JWT_HTTP_PREFIX' in CLIENT_CONFIG:
    warnings.warn(
        "Changing JWT_HTTP_PREFIX breaks compatibility with DBMI services", ResourceWarning)

if 'JWT_COOKIE_NAME' in CLIENT_CONFIG:
    warnings.warn(
        "Changing JWT_COOKIE_NAME breaks compatibility with DBMI services", ResourceWarning)

# Merge client and default configurations
CONFIG = CONFIG_DEFAULTS.copy()
CONFIG.update(CLIENT_CONFIG)


def dbmi_conf(key):
    """
    Just returns the value for the given key
    """
    # Return the value
    return CONFIG[key]
