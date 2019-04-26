#!/usr/bin/env python
"""
This script is a trick to setup a fake Django environment, since this reusable
app will be developed and tested outside any specifiv Django project.
Via ``settings.configure`` you will be able to set all necessary settings
for your app and run the tests as if you were calling ``./manage.py test``.
"""
import sys
from django_nose import NoseTestSuiteRunner
from django.conf import settings

EXTERNAL_APPS = [
    'django.contrib.admin',
    'django.contrib.admindocs',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'django.contrib.sitemaps',
    'django.contrib.sites',
]
INTERNAL_APPS = [
    'django_nose',
    'dbmi_client',
]
INSTALLED_APPS = EXTERNAL_APPS + INTERNAL_APPS

if not settings.configured:
    settings.configure(
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        INSTALLED_APPS=INSTALLED_APPS,
        DBMI_CLIENT_CONFIG={
            "CLIENT": "DBMI-Client",
            "ENVIRONMENT": "prod",
            "AUTH0_TENANTS": "hms-dbmi",
        }
    )


def main(*test_args):
    sys.exit(NoseTestSuiteRunner(verbosity=2, interactive=True).run_tests(test_args))


if __name__ == '__main__':
    main(*sys.argv[1:])
