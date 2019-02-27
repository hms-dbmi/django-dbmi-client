from enum import Enum

import requests
from furl import furl
from rest_framework import status
from django.conf import settings

from dbmi_client.settings import dbmi_settings
from dbmi_client import authn

import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


# Set the possible permissions
class FileserviceRole(Enum):
    Readers = '{}__READERS'.format(dbmi_settings.FILESERVICE_GROUP)
    Writers = '{}__WRITERS'.format(dbmi_settings.FILESERVICE_GROUP)
    Downloaders = '{}__DOWNLOADERS'.format(dbmi_settings.FILESERVICE_GROUP)
    Uploaders = '{}__UPLOADERS'.format(dbmi_settings.FILESERVICE_GROUP)
    admins = '{}__ADMINS'.format(dbmi_settings.FILESERVICE_GROUP)


def check_groups(request):
    """
    This checks Fileservice to ensure the specified group has been created.
    :param request: The current request object
    :return: bool
    """

    # Build the URL
    url = furl(settings.FILESERVICE_URL)
    url.path.segments.extend(['filemaster', 'groups', dbmi_settings.FILESERVICE_GROUP])

    response = None
    try:
        # Make the request
        response = requests.get(url.url, headers=_headers(request))
        response.raise_for_status()

        # Return whether it exists or not
        groups = response.json()
        for group in groups:
            if settings.FILESERVICE_GROUP in group['name']:
                return True

    except requests.HTTPError as e:
        logger.exception(e)
        logger.error('Group check error: {}'.format(response.content))

    except TypeError as e:
        logger.exception(e)
        logger.error('Group check error: {}'.format(response.content))

    return False


def create_file(request, filename, metadata={}, tags=[]):
    """
    Creates a file in Fileservice. This initializes the process by which a file can be stored through
    Fileservice and track metadata/tags.
    :param request: The original request
    :param filename: The filename to use
    :param metadata: Any metadata to include with the file
    :param tags: A list of tags
    :return: The file's UUID
    """

    # Ensure groups exist.
    if not check_groups(request):
        logger.error('Groups do not exist or failed to create')
        return None

    # Build the request.
    data = {
        'permissions': [
            dbmi_settings.FILESERVICE_GROUP
        ],
        'metadata': metadata,
        'filename': filename,
        'tags': tags,
    }

    # Build the URL
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments.extend(['filemaster', 'api', 'file'])

    response = None
    try:
        # Make the request
        response = requests.post(url.url, headers=_headers(request), data=data)

        # Check for known issues
        if response.status_code == status.HTTP_403_FORBIDDEN:
            logger.error('User is forbidden: {}'.format(response))
            raise FileservicePermissionError(response)

        # Check for unexpected errors
        response.raise_for_status()

        # Parse the response
        file = response.json()

        # Get the UUID.
        uuid = file['uuid']

        return uuid

    except requests.HTTPError as e:
        logger.exception(e)
        logger.error('File creation error: {}'.format(response))


def get_file_post(request, uuid):
    """
    This method generates the data for a presigned POST operation for uploading the file to S3. Take the
    returned url and dict and make a POST with your binary file. This will place the file in S3 in a location
    created by Fileservice.
    :param request:
    :param uuid:
    :return:
    """

    # Form the request for the file link
    params = {
        'cloud': 'aws',
        'bucket': dbmi_settings.FILESERVICE_AWS_BUCKET,
        'expires': 100
    }

    # Build the URL
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments.extend(['filemaster', 'api', 'file', uuid, 'post'])

    response = None
    try:
        # Make the request
        response = requests.get(url.url, headers=_headers(request), params=params)

        # Check for known issues
        if response.status_code == status.HTTP_403_FORBIDDEN:
            logger.error('User is forbidden: {}'.format(response))
            raise FileservicePermissionError(response)

        # Check for unexpected errors
        response.raise_for_status()

        # Parse the response
        return response.json()

    except requests.HTTPError as e:
        logger.exception(e)
        logger.error('Get file post error: {}'.format(response))


def set_file_uploaded(request, uuid):

    # Build the URL
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments.extend(['filemaster', 'api', 'file', uuid, 'uploadcomplete'])

    response = None
    try:
        # Make the request
        response = requests.get(url.url, headers=_headers(request))

        # Check for known issues
        if response.status_code == status.HTTP_403_FORBIDDEN:
            logger.error('User is forbidden: {}'.format(response))
            raise FileservicePermissionError(response)

        # Check for unexpected errors
        response.raise_for_status()

        # Parse the response
        return response.ok

    except requests.HTTPError as e:
        logger.exception(e)
        logger.error('Get file post error: {}'.format(response))


def get_file_download(request, uuid):
    """
    Returns an S3 URL to download the requested file. The URL has a limited lifespan and will expire
    after an hour (TODO: Confirm this)
    :param request:
    :param uuid:
    :return:
    """
    # Build the URL
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments.extend(['filemaster', 'api', 'file', uuid, 'download'])

    response = None
    try:
        # Make the request
        response = requests.get(url.url, headers=_headers(request))

        # Check for known issues
        if response.status_code == status.HTTP_403_FORBIDDEN:
            logger.error('User is forbidden: {}'.format(response))
            raise FileservicePermissionError(response)

        # Check for unexpected errors
        response.raise_for_status()

        # Parse the response and return the URL
        download = response.json()

        # Parse the response
        return download.get('url')

    except requests.HTTPError as e:
        logger.exception(e)
        logger.error('Get file post error: {}'.format(response))


def _headers(request):
    """
    Returns the headers to use for Fileservice requests. If a Fileservice token is specified in settings,
    this will use that token to sign calls, otherwise, the current user's JWT will be used.
    :param request: The request
    :return: dict
    """
    if dbmi_settings.FILESERVICE_TOKEN:

        # Use the service token from environment
        return {"Authorization": 'Token {}'.format(dbmi_settings.FILESERVICE_TOKEN), 'Content-Type': 'application/json'}

    else:

        # Get the JWT
        token = authn.get_jwt(request)

        # Use the service token from environment
        return {"Authorization": 'JWT {}'.format(token), 'Content-Type': 'application/json'}


# Indicates the requesting user does not have sufficient permissions for the operation
class FileservicePermissionError(Exception):
    pass


# Indicates the current app's group does not exist
class FileserviceGroupError(Exception):
    pass


# Indicates the current app's targeted bucket does not exist in Fileservice
class FileserviceBucketError(Exception):
    pass
