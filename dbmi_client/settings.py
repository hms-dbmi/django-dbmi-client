from __future__ import absolute_import, unicode_literals

import warnings

from django.conf import settings

# Always import this module as follows:
# from dbmi_client import settings [as dbmi_settings]

# Don't import directly CONFIG or PANELs, or you will miss changes performed
# with override_settings in tests.

# Set service URLs based on environment
DBMI_ENVIRONMENTS = {
    'prod': {
        'AUTHN_URL': 'https://authentication.dbmi.hms.harvard.edu',
        'AUTHZ_URL': 'https://authorization.dbmi.hms.harvard.edu',
        'REG_URL': 'https://registration.dbmi.hms.harvard.edu',
        'JWT_AUTHZ_NAMESPACE': 'https://authorization.dbmi.hms.harvard.edu',
    },
    'dev': {
        'AUTHN_URL': 'https://authentication.aws.dbmi-dev.hms.harvard.edu',
        'AUTHZ_URL': 'https://authorization.aws.dbmi-dev.hms.harvard.edu',
        'REG_URL': 'https://registration.aws.dbmi-dev.hms.harvard.edu',
        'JWT_AUTHZ_NAMESPACE': 'https://authorization.aws.dbmi-dev.hms.harvard.edu',
    }
}

CONFIG_DEFAULTS = {
    # Client options, assume production environment
    'ENVIRONMENT': 'prod',
    'AUTHZ_ADMIN_GROUP': 'dbmi-admin',
    'AUTHZ_USER_GROUP': 'dbmi-user',
    'JWT_HTTP_PREFIX': 'JWT ',
    'JWT_COOKIE_NAME': 'DBMI_JWT',
    'JWT_COOKIE_DOMAIN': '.dbmi.hms.harvard.edu',
    'AUTH0': {
        'CLIENT_IDS': ['!!! must be configured by client !!!'],
        'DOMAIN': 'dbmiauth.auth0.com',
    },
    'AUTHN_BRANDING': {
        'TITLE': 'DBMI Client',
        'ICON_URL': 'https://authentication.dbmi.hms.harvard.edu/static/hms_shield.png',
    },
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

# Ensure environment is set and if not prod or dev, ensure service URLs are provided
if 'ENVIRONMENT' in CLIENT_CONFIG and \
        CLIENT_CONFIG['ENVIRONMENT'].lower() != 'prod' and CLIENT_CONFIG['ENVIRONMENT'].lower() != 'dev':
    warnings.warn(
        "ENVIRONMENT is not set to production, this should be a test environment", ResourceWarning)

    missing_urls = []
    if 'AUTHN_URL' not in CLIENT_CONFIG:
        missing_urls.append('AUTHN_URL')
    if 'AUTHZ_URL' not in CLIENT_CONFIG:
        missing_urls.append('AUTHZ_URL')
    if 'REG_URL' not in CLIENT_CONFIG:
        missing_urls.append('REG_URL')
    if missing_urls:
        raise AttributeError('{} configuration(s) must be set'.format(missing_urls))

    if 'JWT_AUTHZ_NAMESPACE' not in CLIENT_CONFIG:
        warnings.warn(
            "JWT_AUTHZ_NAMESPACE is not set, JWT claims will not be inspected "
            "for groups/roles/permissions", ResourceWarning)

else:

    # Update the client config with pre-defined environment URLs, etc
    CLIENT_CONFIG.update(DBMI_ENVIRONMENTS[CLIENT_CONFIG['ENVIRONMENT']])

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
    if key not in CONFIG:
        warnings.warn("Configuration \'{}\' does not exist".format(key), ResourceWarning)
        return None

    return CONFIG.get(key)
