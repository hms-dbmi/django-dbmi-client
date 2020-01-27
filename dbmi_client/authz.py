from furl import furl
import requests

from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied, NotAuthenticated

from dbmi_client.settings import dbmi_settings
from dbmi_client import authn

# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)

# Set keys for authz dictionary
JWT_AUTHZ_GROUPS = 'groups'
JWT_AUTHZ_ROLES = 'roles'
JWT_AUTHZ_PERMISSIONS = 'permissions'


def jwt_has_authz(claims, auth_type, item):
    """
    Inspects the JWT claims for the permission. This assumed a claims dictionary is
    namespaced under DBMIAuth.dbmi_authz_namespace and 'type' is a key to a list of items
    that 'item' will be compared to. Typically types are group, role, permission. As
    authorization claims in the JWT are not guaranteed, this will return None if those
    claims are missing, indicating the check is inconclusive and another source must
    be checked, likely DBMIAuthz.
    :param claims: The JWT claims dictionary
    :param auth_type: The type of authorization: group, role, permission
    :param item: The specific authorization to check exists for the given type
    :return: None if not defined, bool otherwise
    """
    # Check if enabled
    if not dbmi_settings.JWT_AUTHZ_NAMESPACE:
        logger.debug('JWT_AUTHZ_NAMESPACE is not defined, JWT AuthZ checks are disabled')
        return None

    try:
        # Call the other method with the authz claims object
        auth = claims[dbmi_settings.JWT_AUTHZ_NAMESPACE]
        return auth_has_authz(auth, auth_type, item)

    except (KeyError, IndexError, TypeError, ValueError):
        logger.debug('No authz and/or authz type ({}) in JWT claims'.format(auth_type))

    return None


def auth_has_authz(auth, auth_type, item):
    """
    Inspects the DRF auth object for the permission. This assumed a claims dictionary
    was copied from the namespaced JWT claims to the DRF auth object. See above for info
    on authorization types contained in the JWT.
    :param auth: The DRF auth object
    :param auth_type: The type of authorization: group, role, permission
    :param item: The specific authorization to check exists for the given type
    :return: None if not defined, bool otherwise
    """
    try:
        # Check groups
        for _item in auth[auth_type]:

            # Compare
            if _item == item:
                logger.debug('User has authz: {} - {}'.format(auth_type, item))
                return True

        return False

    except (KeyError, IndexError, TypeError, ValueError):
        logger.debug('No authz and/or authz type ({})'.format(auth_type))

    return None


def has_permission(request_or_jwt, email, item, permission, check_parents=False):
    """
    Consults the DBMIAuthz server for authorization checks. Uses the JWT to
    authenticate the call and checks the returned permissions for the one
    specified.
    :param request_or_jwt: The current request containing the JWT to be checked or the JWT itself
    :param email: The email in the JWT
    :param item: The item string to check for the permission
    :param permission: The permission to be checked for in permissions returned from DBMIAuthz
    :param check_parents: For every item, also attempt to match parents for the given permission
    :return: bool
    """
    url = None
    content = None
    try:
        # Build the request
        url = furl(dbmi_settings.AUTHZ_URL)
        url.path.segments.append('user_permission')
        url.path.segments.append('')
        url.query.params.add('email', email)
        url.query.params.add('client', dbmi_settings.CLIENT)

        # If we are searching parents, we need to fetch all permissions for this user
        if not check_parents:
            url.query.params.add('item', item)

        # Get the JWT token depending on request type
        if type(request_or_jwt) is str:
            token = request_or_jwt
        else:
            token = authn.get_jwt(request_or_jwt)

        # Ensure we've got a token
        if not token:
            return False

        # Build headers for the SciAuthZ call
        headers = {'Authorization': '{}{}'.format(dbmi_settings.JWT_HTTP_PREFIX, token),
                   'Content-Type': 'application/json'}

        # Run it
        response = requests.get(url.url, headers=headers)
        content = response.content
        response.raise_for_status()

        # If checking parents...
        if check_parents and len(item.split('.')) > 1:

            # ... build list of all parent paths
            components = item.lower().split('.')
            items = ['.'.join(components[:i+1]) for i in range(len(components))]

        else:

            # Set the single item list to search
            items = [item.lower()]

        # Parse permissions
        for permission_result in response.json().get('results'):

            # Get the items
            _item = permission_result['item'].lower()
            _permission = permission_result['permission'].lower()

            # Check it
            if _item in items and _permission == permission.lower():
                logger.debug('DBMIAuthZ: {} has {} on {}'.format(email, permission, item))
                return True

    except (requests.HTTPError, TypeError, KeyError):
        logger.error('SciAuthZ permission lookup failed', exc_info=True, extra={
            'request': request_or_jwt, 'email': email, 'permission': permission, 'url': url, 'content': content})

    return False


def has_a_permission(request_or_jwt, email, item, permissions, check_parents=False):
    """
    Consults the DBMIAuthz server for authorization checks. Uses the JWT to
    authenticate the call and checks the returned permissions for the one
    specified.
    :param request_or_jwt: The current request containing the JWT to be checked or the JWT itself
    :param email: The email in the JWT
    :param item: The item string to check for the permission
    :param permissions: A list of permissions
    :param check_parents: For every item, also attempt to match parents for the given permission
    :return: bool
    """
    url = None
    content = None
    try:
        # Build the request
        url = furl(dbmi_settings.AUTHZ_URL)
        url.path.segments.append('user_permission')
        url.path.segments.append('')
        url.query.params.add('email', email)
        url.query.params.add('client', dbmi_settings.CLIENT)

        # If we are searching parents, we need to fetch all permissions for this user
        if not check_parents:
            url.query.params.add('item', item)

        # Get the JWT token depending on request type
        if type(request_or_jwt) is str:
            token = request_or_jwt
        else:
            token = authn.get_jwt(request_or_jwt)

        # Ensure we've got a token
        if not token:
            return False

        # Build headers for the SciAuthZ call
        headers = {'Authorization': '{}{}'.format(dbmi_settings.JWT_HTTP_PREFIX, token),
                   'Content-Type': 'application/json'}

        # Run it
        response = requests.get(url.url, headers=headers)
        content = response.content
        response.raise_for_status()

        # If checking parents...
        if check_parents and len(item.split('.')) > 1:

            # ... build list of all parent paths
            components = item.lower().split('.')
            items = ['.'.join(components[:i+1]) for i in range(len(components))]

        else:

            # Set the single item list to search
            items = [item.lower()]

        # Parse permissions
        for permission_result in response.json().get('results'):

            # Get the items
            item = permission_result['item'].lower()
            permission = permission_result['permission'].lower()

            # Check it
            if item in items and permission in map(str.lower, permissions):
                logger.debug('DBMIAuthZ: {} has {} on {}'.format(email, permission, item))
                return True

    except (requests.HTTPError, TypeError, KeyError):
        logger.error('SciAuthZ permission lookup failed', exc_info=True, extra={
            'request': request_or_jwt, 'email': email, 'permissions': permissions, 'url': url, 'content': content})

    return False


def is_admin(request, email):
    """
    This is just a convenience method that checks the user membership in the AUTHZ_ADMIN_GROUP, or for the
    permission specified in settings as AUTHZ_ADMIN_PERMISSION. It will check the authorization server as
    well as the JWT claims, if any.
    """
    # Check least difficult and move forward
    if jwt_has_authz(authn.get_jwt_payload(request, verify=True),
                     JWT_AUTHZ_GROUPS,
                     dbmi_settings.AUTHZ_ADMIN_GROUP):
        return True

    elif jwt_has_authz(authn.get_jwt_payload(request, verify=True),
                       JWT_AUTHZ_PERMISSIONS,
                       dbmi_settings.AUTHZ_ADMIN_PERMISSION):
        return True

    elif has_permission(request, email, dbmi_settings.CLIENT, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
        return True

    return False


def get_permissions(request_or_jwt, email, item=None):
    """
    Consults the DBMIAuthz server for authorization checks. Uses the JWT to
    authenticate the call and checks the returned permissions for the one
    specified.
    :param request_or_jwt: The current request or JWT to authenticate the call
    :param email: The email in the JWT
    :param item: The item string to check for the permission
    :return: bool
    """
    url = None
    content = None
    try:
        # Build the request
        url = furl(dbmi_settings.AUTHZ_URL)
        url.path.segments.append('user_permission')
        url.path.segments.append('')
        url.query.params.add('email', email)
        url.query.params.add('client', dbmi_settings.CLIENT)

        # Check for specific item
        if item:
            url.query.params.add('item', item)

        # Get the JWT token depending on request type
        if type(request_or_jwt) is str:
            token = request_or_jwt
        else:
            token = authn.get_jwt(request_or_jwt)

        # Ensure we've got a token
        if not token:
            return False

        # Build headers for the SciAuthZ call
        headers = {'Authorization': '{}{}'.format(dbmi_settings.JWT_HTTP_PREFIX, token),
                   'Content-Type': 'application/json'}

        # Run it
        response = requests.get(url.url, headers=headers)
        content = response.content
        response.raise_for_status()

        return response.json().get('results', [])

    except (requests.HTTPError, TypeError, KeyError):
        logger.error('SciAuthZ permission lookup failed', exc_info=True, extra={
            'email': email, 'url': url, 'content': content, 'item': item})

    return []


###################################################################
#
# Django Rest Framework (DRF) Custom Authorization
#
###################################################################


class DBMIAdminPermission(BasePermission):
    """
    Permission check for MANAGE permissions on DBMI client
    """

    def has_permission(self, request, view):

        # Get the email of the authenticated user
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' attribute on request')
            raise PermissionDenied

        # Ensure claims are setup and then check them first, as it is least costly.
        if request.auth:
            if auth_has_authz(request.auth, JWT_AUTHZ_GROUPS, dbmi_settings.AUTHZ_ADMIN_GROUP):
                return True

        # Check permissions
        if has_permission(request, request.user, dbmi_settings.CLIENT, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
            return True

        # Possibly store these elsewhere for records
        logger.info('{} Failed MANAGE permission for DBMI'.format(request.user))

        raise PermissionDenied


class DBMIItemPermission(BasePermission):
    """
    This permission class is meant to be inherited by clients who need to specify
    custom item strings for their permission checks. Set the item string and the permission
    and the base implementation will check the DBMI AuthZ server.
    """

    # The permission item string to check
    item = 'dbmi.item.subitem'

    # The permission itself the requesting user must have for this item
    permission = 'manage'

    def has_permission(self, request, view):

        # Get the email
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' (JWT email) attribute on request')
            raise NotAuthenticated

        # Check permission server for admin permissions
        if has_permission(request, request.user, self.item, self.permission):
            return True

        raise PermissionDenied


class DBMIUserPermission(BasePermission):
    """
    Custom permission to only any authenticated user access.
    """

    def has_object_permission(self, request, view, obj):

        # Get the email
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' (JWT email) attribute on request')
            raise NotAuthenticated

        return True


class DBMIOwnerPermission(BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has an `email` attribute.
    """

    def has_object_permission(self, request, view, obj):

        # Get the email
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' (JWT email) attribute on request')
            raise NotAuthenticated

        # Check if a key has been specified
        key = dbmi_settings.DRF_OBJECT_OWNER_KEY
        if key:

            # Ensure the attribute exists
            if not hasattr(obj, key):
                logger.error('Ownership key "{}" for object "{}" does not exist'.format(key, obj))

            else:
                logger.debug('Comparing key "{}" on "{}" for ownership'.format(key, obj))
                return getattr(obj, key) == request.user

        else:
            logger.debug('No key specified, trying attrs "email", "user" on "{}" for ownership'.format(key, obj))

            # Check email attribute
            if hasattr(obj, 'email') and obj.email == request.user:
                return True

            # Check for a user attribute
            if hasattr(obj, 'user') and obj.user == request.user:
                return True

        raise PermissionDenied


class DBMIAdminOrOwnerPermission(DBMIOwnerPermission):
    """
    Permission check for owner or MANAGE permissions on DBMI 'obj'. Owner is determined
    by comparing email in JWT with that of the email property on 'obj'
    """
    message = 'User does not have proper permission on item DBMI'

    def has_object_permission(self, request, view, obj):

        # Check ownership first
        try:
            return super(DBMIAdminOrOwnerPermission, self).has_object_permission(request, view, obj)

        except PermissionDenied:
            logger.debug('Is not owner of object, checking for admin/manage...')

        # Ensure claims are setup and then check them first, as it is least costly.
        if request.auth:
            if auth_has_authz(request.auth, JWT_AUTHZ_PERMISSIONS, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
                return True

        # Lastly, check permission server for admin permissions
        if has_permission(request, request.user, dbmi_settings.CLIENT, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
            return True

        # Possibly store these elsewhere for records
        logger.info('{} Failed MANAGE or owner permission for DBMI'.format(request.user))

        raise PermissionDenied
