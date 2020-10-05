import base64
import json
from enum import Enum

import requests
from furl import furl

from dbmi_client.settings import dbmi_settings
from dbmi_client import authn

import logging

logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


# Set the possible permissions
class FileserviceRole(Enum):
    Readers = "{}__READERS".format(dbmi_settings.FILESERVICE_GROUP)
    Writers = "{}__WRITERS".format(dbmi_settings.FILESERVICE_GROUP)
    Downloaders = "{}__DOWNLOADERS".format(dbmi_settings.FILESERVICE_GROUP)
    Uploaders = "{}__UPLOADERS".format(dbmi_settings.FILESERVICE_GROUP)
    admins = "{}__ADMINS".format(dbmi_settings.FILESERVICE_GROUP)

    @classmethod
    def roles(cls):
        return [f.value for f in FileserviceRole]


def create_group():
    """
    Checks Fileservice to ensure it is setup and configured to manage the passed bucket(s)
    with the passed admin(s).
    """
    # Group was not found, create it, specifying passed admins
    data = {
        "name": dbmi_settings.FILESERVICE_GROUP.upper(),
        "users": [{"email": email} for email in dbmi_settings.FILESERVICE_ADMINS],
        "buckets": [{"name": b} for b in dbmi_settings.FILESERVICE_BUCKETS],
    }

    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "groups", ""]

    # Make the request
    groups = _request(method="post", url=url.url, data=json.dumps(data))
    if not groups:
        logger.info("Failed to create groups")
        return False

    # Make the request.
    data = {"buckets": [{"name": b} for b in dbmi_settings.FILESERVICE_BUCKETS]}
    for group in groups:

        # Make the URL
        url = furl(dbmi_settings.FILESERVICE_URL)
        url.path.segments = ["filemaster", "groups", group["id"], ""]

        # Make the request
        response = _request(method="put", url=url.url, data=json.dumps(data))
        if response:
            logger.info('Added buckets "{}" to group "{}"'.format(dbmi_settings.FILESERVICE_BUCKETS, group["name"]))
        else:
            logger.info(
                'Failed to add buckets "{}" to group "{}"'.format(dbmi_settings.FILESERVICE_BUCKETS, group["name"])
            )

    return True


def check_group():
    """
    Checks Fileservice to ensure it is setup and configured to manage the files for passed group.
    :return: Whether Fileservice is configured or not
    :rtype: bool
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "groups", ""]

    # Make the request
    groups = _request(method="get", url=url.url)
    if groups is None:
        logger.info("Getting groups failed")
        return False

    # Check for the required group.
    for group in groups:
        if group["name"] in FileserviceRole.roles():
            return True

    return False


def create_archivefile(filename, metadata=None, tags=None):
    """
    Create an ArchiveFile record for the give parameters and returns Fileservice's response.
    :param filename: The filename of the file
    :param metadata: A dictionary of metadata
    :param tags: A list of tags
    :return:
    """
    # Build the request.
    data = {
        "permissions": [
            dbmi_settings.FILESERVICE_GROUP,
        ],
        "filename": filename,
    }

    # Check for and add optional data
    if metadata:
        data["metadata"] = metadata
    if tags:
        data["tags"] = tags

    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", ""]

    # Make the request
    file = _request(method="post", url=url.url, data=json.dumps(data))

    return file


def create_archivefile_upload(filename, metadata=None, tags=None, bucket=None, conditions=None):
    """
    Create a file and generate the presigned S3 POST for sending the file to S3. Allows for specification
    of additional parameters for the upload.
    :param filename: The filename of the file
    :param metadata: A dictionary of metadata
    :param tags: A list of tags
    :param bucket: The bucket to which the upload is going
    :param conditions: A list of S3 conditions to pass along when creating the signature for the post
    :return: File UUID, POST data for file upload
    """
    # Check bucket
    if not bucket:
        if dbmi_settings.FILESERVICE_BUCKETS:
            bucket = dbmi_settings.FILESERVICE_BUCKETS[0]
        else:
            raise ValueError("Cannot upload file without bucket specified")

    # Make the request.
    file = create_archivefile(filename=filename, metadata=metadata, tags=tags)

    # Get the UUID.
    uuid = file["uuid"]

    # Form the request for the file link
    params = {"cloud": "aws", "bucket": bucket, "expires": 100}

    # Add conditions if passed
    if conditions:
        params["conditions"] = base64.b64encode(json.dumps(conditions).encode()).decode()

    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "post", ""]
    url.query.params = params

    # Make the request
    data = _request(method="get", url=url.url)

    return uuid, data


def get_archivefiles(uuids=None):
    """
    Accepts a list of Fileservice UUIDs and returns a list of the ArchiveFile dictionaries
    from Fileservice
    :param uuids: A list of Fileservice UUIDs
    :type uuids: list
    :return: A list of ArchiveFile dictionaries
    :rtype: list
    """
    # Build the request.
    if uuids and type(uuids) is str:
        params = {"uuids": uuids}
    elif uuids and type(uuids) is list:
        params = {"uuids": ",".join(uuids)}
    else:
        params = {}

    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", ""]
    url.query.params = params

    # Make the request
    files = _request(method="get", url=url.url)
    if files:
        return files
    else:
        return []


def get_archivefile(uuid):
    """
    Accepts a Fileservice UUID and returns an ArchiveFile dictionary from Fileservice
    :param uuid: A Fileservice UUID
    :type uuid: str
    :return: An ArchiveFile dictionaries
    :rtype: dict
    """
    # Make the request.
    return next(iter(get_archivefiles([uuid])), None)


def get_archivefile_url(uuid):
    """
    Retrieves the ArchiveFile Fileservice download URL. Performing a GET to this
    URL will generate a pre-signed URL to download the actual file from the
    storage location (S3 bucket).
    :param uuid: The UUID of the ArchiveFile for which the hash has been requested
    :type uuid: str
    :return: The file's hash
    :rtype: str
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "download", ""]
    return url.url


def get_archivefile_hash(uuid):
    """
    Retrieves the file hash from the storage provider (or Fileservice). This is
    typically an MD5 hash.
    :param uuid: The UUID of the ArchiveFile for which the hash has been requested
    :type uuid: str
    :return: The file's hash
    :rtype: str
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "filehash", ""]

    # Make the request
    hash = _request(method="get", url=url.url)
    return hash


def update_archivefile(uuid, file):
    """
    Accepts details on an ArchiveFile object on Fileservice
    :param uuid: The UUID of the ArchiveFile to update
    :type uuid: str
    :param file: The file dictionary specifying ArchiveFile updates
    :type file: dict
    :return: The updated ArchiveFile dictionary
    :rtype: dict
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, ""]

    # Make the request
    file = _request(method="patch", url=url.url, data=json.dumps(file))
    return file


def copy_archivefile(uuid, bucket):
    """
    Copy the requested file to the new bucket
    :param uuid: The file's Fileservice UUID
    :param bucket: The destination S3 bucket
    :return: The result of the operation
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "copy", ""]
    url.query.params.add("to", bucket)

    # Make the request
    file = _request(method="post", url=url.url)
    return file


def move_archivefile(uuid, bucket):
    """
    Move the requested file to the new bucket
    :param uuid: The file's Fileservice UUID
    :param bucket: The destination S3 bucket
    :return: The result of the operation
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "move", ""]
    url.query.params.add("to", bucket)

    # Make the request
    file = _request(method="post", url=url.url)
    return file


def delete_archivefile(uuid, location):
    """
    Delete the requested file from the passed location
    :param uuid: The file's Fileservice UUID
    :param location: The file's location to delete (if in multiple locations)
    :return: The result of the operation
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, ""]
    url.query.params.add("location", location)

    # Make the request
    file = _request(method="delete", url=url.url)
    return file


def uploaded_archivefile(uuid, location_id):
    """
    Informs Fileservice that the ArchiveFile's actual file has been successfully uploaded to the
    storage location (S3 bucket). Fileservice will run routines to inspect the final location of the
    file and ensure its metadata is updated within Fileservice.
    :param uuid: The UUID of the ArchiveFile being uploaded
    :type uuid: str
    :param location_id: The ID of the location generated by the ArchiveFile creation
    :type location_id: str
    :return: The success of the update operation
    :rtype: bool
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "uploadcomplete", ""]
    url.query.params.add("location", location_id)

    # Make the request
    file = _request(method="get", url=url.url)
    return file


def get_archivefile_download_url(uuid):
    """
    Returns a URL by which the file's data can be downloaded from Fileservice's storage location (S3 bucket).
    The URL will point directly to the file's storage location, likely an S3 bucket/key formatted URL.
    Authentication/authorization is embedded into the URL via AWS pre-signed query but the link will have
    limited life before it's validity will expire (typically 24 hours).
    :param uuid: The UUID of the file to download
    :type uuid: str
    :return: The download URL
    :rtype: str
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "download", ""]

    # Make the request
    file = _request(method="get", url=url.url)
    return file["url"]


def download_archivefile(uuid):
    """
    Downloads a file from Fileservice's storage location (S3 bucket).
     This downloads the file directly and returns the bytes of said file. This download
    occurs synchronously and is not recommended for files of significant size.
    :param uuid: The UUID of the file to download
    :type uuid: str
    :return: The raw bytes of the file from S3
    :rtype: bytes
    """
    # Get the URL
    url = get_archivefile_download_url(uuid)

    # Request the file from S3 and get its contents.
    response = requests.get(url)

    # Add the content to the FHIR resource as a data element and remove the URL element.
    return response.content


def get_archivefile_proxy_url(uuid):
    """
    Returns a URL by which the file's data can be downloaded from Fileservice's storage location (S3 bucket),
    as proxied through Fileservice. Thus, a requesting entity must be able to properly authenticate/authorize
    with Fileservice.
    :param uuid: The UUID of the file to download
    :type uuid: str
    :return: The proxy download URL
    :rtype: str
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "proxy", ""]
    return url.url


def proxy_archivefile(uuid):
    """
    Downloads a file from Fileservice's storage location (S3 bucket) using the Nginx file proxy
    mechanism. This downloads the file directly and returns the bytes of said file. This download
    occurs synchronously and is not recommended for files of significant size.
    :param uuid: The UUID of the file to download
    :type uuid: str
    :return: The raw bytes of the file from S3
    :rtype: bytes
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", uuid, "proxy", ""]

    # Make the request
    response = _request(method="get", url=url.url, raw=True)

    # Return the data
    return response.content


def download_archivefiles(uuids):
    """
    Accepts a list of Fileservice UUIDs and builds a download of an archive containing those files.
    The object returned is the raw bytes of the archive containing the requested files. The download
    takes place synchronously and is not recommended for files of significant size.
    :param uuids: A list of UUIDs to include in the archive
    :type uuids: list
    :return: The raw data of the archive
    :rtype: bytes
    """
    # Make the URL.
    url = furl(dbmi_settings.FILESERVICE_URL)
    url.path.segments = ["filemaster", "api", "file", "archive", ""]
    url.query.params.add("uuids", ",".join(uuids))

    # Make the request
    response = _request(method="get", url=url.url, raw=True)

    # Return the data
    return response.content


def _request(method, url, request=None, raw=False, **kwargs):
    """
    This wraps the logic and error-handling required of making a RESTful request to a service
    :param method: The request method (get, post, put, delete, etc)
    :param url: The URL to make the request to
    :param request: The current request object
    :param raw: Return the raw response object
    :return: object
    """
    # Make the request, catch failures, and return response, if any
    response = None
    try:
        # Make the request
        response = getattr(requests, method)(url, headers=_headers(request), **kwargs)
        response.raise_for_status()

        # Determine what to return
        if raw:
            return response
        else:
            return response.json()

    except Exception as e:
        logger.debug("Request/{} failed -> {}: {}".format(method, url, getattr(response, "content", "<empty>")))
        logger.exception(
            "Request error: {}".format(e),
            exc_info=True,
            extra={"response": response, "method": method, "url": url, **kwargs},
        )

    # Determine what to return
    if raw:
        return response
    else:
        return None


def _headers(request=None):
    """
    Returns the headers to use for Fileservice requests. If a Fileservice token is specified in settings,
    this will use that token to sign calls, otherwise, the current user's JWT will be used.
    :param request: The request
    :return: dict
    """
    if dbmi_settings.FILESERVICE_TOKEN:

        # Use the service token from environment
        return {"Authorization": "Token {}".format(dbmi_settings.FILESERVICE_TOKEN), "Content-Type": "application/json"}

    elif request:

        # Get the JWT
        token = authn.get_jwt(request)

        # Use the service token from environment
        return {"Authorization": "JWT {}".format(token), "Content-Type": "application/json"}

    else:
        raise ValueError("Cannot properly authenticate service call")


# Indicates the requesting user does not have sufficient permissions for the operation
class FileservicePermissionError(Exception):
    pass


# Indicates the current app's group does not exist
class FileserviceGroupError(Exception):
    pass


# Indicates the current app's targeted bucket does not exist in Fileservice
class FileserviceBucketError(Exception):
    pass
