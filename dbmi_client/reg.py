from furl import furl
import requests
import json
import base64

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
    profile["email"] = email

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(["api", "register", ""])

    response = requests.post(url.url, headers=authn.dbmi_http_headers(request), data=json.dumps(profile))
    if not response.ok:
        logger.error("Create user response: {}".format(response.content))

    return response.json()


def get_dbmi_user(request, email=None):
    logger.debug("Get DBMI user")

    # Get the JWT
    if not email:
        email = authn.get_jwt_email(request, verify=False)

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(["api", "register", ""])

    # Add email
    url.query.params.add("email", email)

    # Requests for profiles are limited to the profile for the requesting user
    response = requests.get(url.url, headers=authn.dbmi_http_headers(request))
    if not response.ok:
        logger.error("Get user response: {}".format(response.content))

    # Return the profile
    profiles = response.json()["results"]
    return next(iter(profiles), None)


def update_dbmi_user(request, **profile):
    logger.debug("Update DBMI user")

    # Get the JWT
    email = authn.get_jwt_email(request, verify=False)

    # Get their profile first
    reg_profile = get_dbmi_user(request=request, email=email)
    if not reg_profile:

        # Ensure email is in their profile
        if "email" not in profile:
            profile["email"] = email

        # Create the profile
        return create_dbmi_user(request, **profile)

    else:
        # Build the URL (needs trailing slash)
        url = furl(dbmi_settings.REG_URL)
        url.path.segments.extend(["api", "register", reg_profile["id"], ""])

        response = requests.put(url.url, headers=authn.dbmi_http_headers(request), data=json.dumps(profile))
        if not response.ok:
            logger.error("Update user response: {}".format(response.content))

        return response.json()


def send_email_confirmation(request, success_url, title=None, icon=None, subject=None):
    logger.debug("Sending confirmation email")

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(["api", "register", "send_confirmation_email", ""])

    # Add extra data to define look and feel of email, if passed
    branding = {}
    if title:
        branding["title"] = title
    if icon:
        branding["icon"] = icon
    if subject:
        branding["subject"] = subject

    # Set data for request
    data = {
        "success_url": success_url,
    }

    # Check for branding
    if branding:
        data["branding"] = base64.b64encode(json.dumps(branding).encode()).decode()

    # Make the call
    response = requests.post(url.url, headers=authn.dbmi_http_headers(request), data=json.dumps(data))
    if not response.ok:
        logger.error("Confirmation email response: {}".format(response.content))

    return response.ok


def check_email_confirmation(request):
    logger.debug("Checking email confirmation")

    # Build the URL (needs trailing slash)
    url = furl(dbmi_settings.REG_URL)
    url.path.segments.extend(["api", "register", ""])
    url.query.params.add("email", authn.get_jwt_email(request, verify=False))

    # Make the call
    response = requests.get(url.url, headers=authn.dbmi_http_headers(request))
    if not response.ok:
        logger.error("Confirmation email response: {}".format(response.content))
        return None

    try:
        # Parse the profile for the status
        email_status = response.json()["results"][0]["email_confirmed"]
        logger.debug("Email confirmation status: {}".format(email_status))

        return email_status

    except (KeyError, IndexError) as e:
        logger.error("Failed parsing profile: {}".format(e))

    return None
