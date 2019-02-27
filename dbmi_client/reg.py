from furl import furl
import requests
import json

from dbmi_client import authn
from dbmi_client.settings import dbmi_settings


# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


def create_dbmi_user(request, **profile):
    logger.debug("Creating DBMI user")

    # Get the JWT
    email = authn.get_jwt_email(request, verify=False)

    # Update kwargs
    profile['email'] = email

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(['api', 'register', ''])

    response = requests.post(url.url, headers=authn.dbmi_http_headers(request), data=json.dumps(profile))
    if not response.ok:
        logger.error('Create user response: {}'.format(response.content))

    return response


def send_email_confirmation(request, success_url):
    logger.debug("Sending confirmation email")

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(['api', 'register', 'send_confirmation_email', ''])

    data = {
        'success_url': success_url
    }

    # Make the call
    response = requests.post(url.url, headers=authn.dbmi_http_headers(request), data=json.dumps(data))
    if not response.ok:
        logger.error('Confirmation email response: {}'.format(response.content))

    return response.ok


def check_email_confirmation(request):
    logger.debug("Checking email confirmation")

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(['api', 'register', ''])
    url.query.params.add('email', authn.get_jwt_email(request, verify=False))

    # Make the call
    response = requests.get(url.url, headers=authn.dbmi_http_headers(request))
    if not response.ok:
        logger.error('Confirmation email response: {}'.format(response.content))
        return None

    try:
        # Parse the profile for the status
        email_status = response.json()['results'][0]['email_confirmed']
        logger.debug('Email confirmation status: {}'.format(email_status))

        return email_status

    except (KeyError, IndexError) as e:
        logger.error('Failed parsing profile: {}'.format(e))

    return None


