from django.core.exceptions import PermissionDenied

from dbmi_client.settings import dbmi_conf
from dbmi_client import authn
from dbmi_client import authz

import logging
logger = logging.getLogger(__name__)


def dbmi_user(view):
    '''
    Decorator to only check if the current user's JWT is valid
    :param function:
    :type function:
    :return:
    :rtype:
    '''
    def wrap(request, *args, **kwargs):

        # Get the token
        token = authn.get_jwt(request)
        if not token:
            return authn.logout_redirect(request)

        # User has a valid JWT from SciAuth
        if authn.validate_rs256_jwt(token):
            return view(request, *args, **kwargs)

        else:
            return authn.logout_redirect(request)

    return wrap


def dbmi_admin(view):
    '''
    Decorator to check for valid JWT and admin permissions
    :param function:
    :type function:
    :return:
    :rtype:
    '''
    def wrap(request, *args, **kwargs):

        # Get the token
        token = authn.get_jwt(request)
        if not token:
            return authn.logout_redirect(request)

        # Validate request
        payload = authn.validate_rs256_jwt(token)
        if not payload:
            return authn.logout_redirect(request)

        # Check claims in the JWT first, as it is least costly.
        if authz.has_authz_claim(payload, authz.JWT_AUTHZ_GROUPS, dbmi_conf('AUTHZ_ADMIN_GROUP')):
            return view(request, *args, **kwargs)

        # Now consult the AuthZ server
        if authz.has_permission(request, payload.get('email'), authz.DBMI_ADMIN_PERMISSION):
            return view(request, *args, **kwargs)

        # Possibly store these elsewhere for records
        # TODO: Figure out a better way to flag failed access attempts
        logger.warning('{} Failed {} permission on {}'.format(payload.get('email'),
                                                              authz.DBMI_ADMIN_PERMISSION,
                                                              dbmi_conf('CLIENT')))

        raise PermissionDenied

    return wrap


def dbmi_group(group):
    '''
    Decorator that accepts a group and checks the request user to see if they
    belong to said group.
    :param group: The group
    :type group: str
    :return: function
    '''

    def real_decorator(view):

        def wrap(request, *args, **kwargs):

            # Validates the JWT and returns its payload if valid.
            jwt_payload = authn.validate_request(request)

            # User has a valid JWT from SciAuth
            if jwt_payload is not None:

                # Get the email
                email = jwt_payload.get('email')

                # Check claims in the JWT first, as it is least costly.
                if authz.has_authz_claim(jwt_payload, authz.JWT_AUTHZ_GROUPS, group):
                    return view(request, *args, **kwargs)

                # Possibly store these elsewhere for records
                # TODO: Figure out a better way to flag failed access attempts
                logger.warning('{} Failed {} group on {}'.format(email, group, dbmi_conf('CLIENT')))

                # Forbid if nothing else
                raise PermissionDenied

            else:
                logger.debug('Missing/invalid JWT, sending to login')
                return authn.logout_redirect(request)

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_permission(permission):
    '''
    Decorator that accepts an item string that is used to retrieve
    permissions from SciAuthZ.
    :param permission: The permission
    :type permission: str
    :return: function
    '''

    def real_decorator(view):

        def wrap(request, *args, **kwargs):

            # Validates the JWT and returns its payload if valid.
            jwt_payload = authn.validate_request(request)

            # User has a valid JWT from SciAuth
            if jwt_payload is not None:

                # Get the email
                email = jwt_payload.get('email')

                # Check claims in the JWT first, as it is least costly.
                if authz.has_authz_claim(jwt_payload, authz.JWT_AUTHZ_PERMISSIONS, permission):
                    return view(request, *args, **kwargs)

                # Check permission
                if authz.has_permission(request, email, permission):
                    return view(request, *args, **kwargs)

                # Possibly store these elsewhere for records
                # TODO: Figure out a better way to flag failed access attempts
                logger.warning('{} Failed {} permission on {}'.format(email, permission, dbmi_conf('CLIENT')))

                # Forbid if nothing else
                raise PermissionDenied

            else:
                logger.debug('Missing/invalid JWT, sending to login')
                return authn.logout_redirect(request)

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_role(role):
    '''
    Decorator that accepts an item string that is used to retrieve
    roles from JWT AuthZ claims.
    :param role: The role
    :type role: str
    :return: function
    '''

    def real_decorator(view):

        def wrap(request, *args, **kwargs):

            # Validates the JWT and returns its payload if valid.
            jwt_payload = authn.validate_request(request)

            # User has a valid JWT from SciAuth
            if jwt_payload is not None:

                # Get the email
                email = jwt_payload.get('email')

                # Check claims in the JWT first, as it is least costly.
                if authz.has_authz_claim(jwt_payload, authz.JWT_AUTHZ_ROLES, role):
                    return view(request, *args, **kwargs)

                # Possibly store these elsewhere for records
                # TODO: Figure out a better way to flag failed access attempts
                logger.warning('{} Failed {} role check on {}'.format(email, role, dbmi_conf('CLIENT')))

                # Forbid if nothing else
                raise PermissionDenied

            else:
                logger.debug('Missing/invalid JWT, sending to login')
                return authn.logout_redirect(request)

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator
