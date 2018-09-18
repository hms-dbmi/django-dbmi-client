from furl import furl
import requests

from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied

from dbmi_client.settings import dbmi_conf
from dbmi_client import authn

from dbmi_client.settings import get_logger
logger = get_logger()

# Set keys for authz dictionary
JWT_AUTHZ_GROUPS = 'groups'
JWT_AUTHZ_ROLES = 'roles'
JWT_AUTHZ_PERMISSIONS = 'permissions'

# We need at minimum an admin group for admin level permissions
DBMI_ADMIN_PERMISSION = 'MANAGE'


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
    try:
        # Call the other method with the authz claims object
        auth = claims[dbmi_conf('JWT_AUTHZ_NAMESPACE')]
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


def has_permission(request, email, permission):
    """
    Consults the DBMIAuthz server for authorization checks. Uses the JWT to
    authenticate the call and checks the returned permissions for the one
    specified.
    :param request: The current request containing the JWT to be checked
    :param email: The email in the JWT
    :param permission: The permission to be checked for in permissions returned from DBMIAuthz
    :return: bool
    """
    url = None
    content = None
    try:
        # Build the request
        url = furl(dbmi_conf('AUTHZ_URL'))
        url.path.segments.append('user_permission')
        url.query.params.add('email', email)
        url.query.params.add('item', dbmi_conf('CLIENT'))

        # Get the JWT token depending on request type
        token = authn.get_jwt(request)
        if not token:
            return False

        # Build headers for the SciAuthZ call
        headers = {'Authorization': '{}{}'.format(dbmi_conf('JWT_HTTP_PREFIX'), token),
                   'Content-Type': 'application/json'}

        # Run it
        response = requests.get(url.url, headers=headers)
        content = response.content
        response.raise_for_status()

        # Parse permissions
        for permission_result in response.json().get('results'):
            if permission_result['permission'].lower() == permission.lower():
                logger.debug('DBMIAuthZ: {} has {} on {}'.format(email, permission, dbmi_conf('CLIENT')))
                return True

    except (requests.HTTPError, TypeError, KeyError):
        logger.error('SciAuthZ permission lookup failed', exc_info=True, extra={
            'request': request, 'email': email, 'permission': permission, 'url': url, 'content': content})

    return False


###################################################################
#
# Django Rest Framework (DRF) Custom Authorization
#
###################################################################


class DBMIManagePermission(BasePermission):
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
            if auth_has_authz(request.auth, JWT_AUTHZ_PERMISSIONS, DBMI_ADMIN_PERMISSION):
                return True

        # Check permissions
        if has_permission(request, request.user, DBMI_ADMIN_PERMISSION):
            return True

        # Possibly store these elsewhere for records
        logger.info('{} Failed MANAGE permission for DBMI'.format(request.user))

        raise PermissionDenied


class DBMIManageOrOwnerPermission(BasePermission):
    """
    Permission check for owner or MANAGE permissions on DBMI 'obj'. Owner is determined
    by comparing email in JWT with that of the email property on 'obj'
    """
    message = 'User does not have proper permission on item DBMI'

    def has_object_permission(self, request, view, obj):

        # Get the email of the authenticated user
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' attribute on request')
            raise PermissionDenied

        # JWT email must be related to given object email
        if hasattr(obj, 'email') and obj.email == request.user:
            return True

        # Check for a user attribute
        if hasattr(obj, 'user') and obj.user == request.user:
            return True

        # Ensure claims are setup and then check them first, as it is least costly.
        if request.auth:
            if auth_has_authz(request.auth, JWT_AUTHZ_PERMISSIONS, DBMI_ADMIN_PERMISSION):
                return True

        # Lastly, check permission server for admin permissions
        if has_permission(request, request.user, DBMI_ADMIN_PERMISSION):
            return True

        # Possibly store these elsewhere for records
        logger.info('{} Failed MANAGE or owner permission for DBMI'.format(request.user))

        raise PermissionDenied


class DBMIOwnerPermission(BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has an `email` attribute.
    """

    def has_object_permission(self, request, view, obj):

        # Get the email
        if not hasattr(request, 'user'):
            logger.warning('No \'user\' (JWT email) attribute on request')
            raise PermissionDenied

        # JWT email must be related to given object email
        if hasattr(obj, 'email') and obj.email == request.user:
            return True

        # Check for a user attribute
        if hasattr(obj, 'user') and obj.user == request.user:
            return True

        raise PermissionDenied
