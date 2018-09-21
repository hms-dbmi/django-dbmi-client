from django.core.exceptions import PermissionDenied
from django.contrib import auth as django_auth

from dbmi_client.settings import dbmi_conf
from dbmi_client import authn
from dbmi_client import authz

from dbmi_client.settings import get_logger
logger = get_logger()


def dbmi_user(view):
    '''
    Decorator to only check if the current user's JWT is valid
    :param function:
    :type function:
    :return:
    :rtype:
    '''
    def wrap(request, *args, **kwargs):

        # Validate request
        token, payload = _token_auth(request)
        if not token:
            return authn.logout_redirect(request)

        # Check if we are using model auth
        if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
            logger.debug('JWT checked out but user could not be created/fetched from model')
            return authn.logout_redirect(request)

        # Let it go
        return view(request, *args, **kwargs)

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

        # Validate request
        token, payload = _token_auth(request)
        if not token:
            return authn.logout_redirect(request)

        # Check if we are using model auth
        if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
            logger.debug('JWT checked out but user could not be created/fetched from model')
            return authn.logout_redirect(request)

        # Check claims in the JWT first, as it is least costly.
        if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, dbmi_conf('AUTHZ_ADMIN_GROUP')):
            return view(request, *args, **kwargs)

        # Get their email address
        email = authn.get_jwt_email(request, verify=False)

        # Now consult the AuthZ server
        if authz.has_permission(request, email, dbmi_conf('CLIENT'), dbmi_conf('AUTHZ_ADMIN_PERMISSION')):
            return view(request, *args, **kwargs)

        # Possibly store these elsewhere for records
        # TODO: Figure out a better way to flag failed access attempts
        logger.warning('{} Failed {} permission on {}'.format(email,
                                                              dbmi_conf('AUTHZ_ADMIN_PERMISSION'),
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

            # Validate request
            token, payload = _token_auth(request)
            if not token:
                return authn.logout_redirect(request)

            # Check if we are using model auth
            if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
                logger.debug('JWT checked out but user could not be created/fetched from model')
                return authn.logout_redirect(request)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, group):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning('{} Failed {} group on {}'.format(payload.get('email'), group, dbmi_conf('CLIENT')))

            # Forbid if nothing else
            raise PermissionDenied

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

            # Validate request
            token, payload = _token_auth(request)
            if not token:
                return authn.logout_redirect(request)

            # Check if we are using model auth
            if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
                logger.debug('JWT checked out but user could not be created/fetched from model')
                return authn.logout_redirect(request)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_ROLES, role):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning('{} Failed {} group on {}'.format(payload.get('email'), role, dbmi_conf('CLIENT')))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_app_permission(permission):
    '''
    Decorator that accepts an item string that is used to retrieve
    permissions from SciAuthZ.
    :param permission: The permission
    :type permission: str
    :return: function
    '''

    def real_decorator(view):

        def wrap(request, *args, **kwargs):

            # Validate request
            token, payload = _token_auth(request)
            if not token:
                return authn.logout_redirect(request)

            # Check if we are using model auth
            if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
                logger.debug('JWT checked out but user could not be created/fetched from model')
                return authn.logout_redirect(request)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_PERMISSIONS, permission):
                return view(request, *args, **kwargs)

            # Get their email address
            email = authn.get_jwt_email(request, verify=False)

            # Check permission on the app
            if authz.has_permission(request, email, dbmi_conf('CLIENT'), permission):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning('{} Failed {} permission on {}'.format(email, permission, dbmi_conf('CLIENT')))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_item_permission(item, permission):
    '''
    Decorator that accepts an item string that is checked for the passed permission. Item is an arbitrary
    string the application uses internally for specific or object-level permissions.
    :param item: The item
    :type item: str
    :param permission: The permission
    :type permission: str
    :return: function
    '''

    def real_decorator(view):

        def wrap(request, *args, **kwargs):

            # Validate request
            token, payload = _token_auth(request)
            if not token:
                return authn.logout_redirect(request)

            # Check if we are using model auth
            if dbmi_conf('USER_MODEL_ENABLED') and not _model_auth(request, token):
                logger.debug('JWT checked out but user could not be created/fetched from model')
                return authn.logout_redirect(request)

            # Get their email address
            email = authn.get_jwt_email(request, verify=False)

            # Check permission
            if authz.has_permission(request, email, item, permission):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning('{} Failed {} permission on {}'.format(email, permission, dbmi_conf('CLIENT')))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def _token_auth(request):
    """
    Accepts the request and checks for a valid JWT. If it exists, the payload is returned
    :param request: The incoming request
    :return: The JWT payload dict
    """
    # Get the token
    token = authn.get_jwt(request)
    if not token:
        return None, None

    # Validate request
    payload = authn.validate_rs256_jwt(token)
    if not payload:
        return None, None

    return token, payload


def _model_auth(request, token):
    """
    Accepts the request and the JWT and ensures the User model is brought into the mix
    and the user instance properly authenticated and attached to the request.
    :param request: The incoming request
    :param token: The verified JWT
    :return: Whether the model authenticated succeeded or not
    """
    # Check if already authenticated
    if request.user.is_authenticated():
        return True

    # Clear user
    request.user = None

    # Log the user in through Django's auth system
    user = django_auth.authenticate(request=request, token=token)
    if user:

        # Log them in
        authn.login(request, user)
        return True

    else:
        logger.warning("Could not log user in: {}".format(authn.get_jwt_email(request, verify=False)))

    return False
