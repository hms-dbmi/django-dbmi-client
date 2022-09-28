from django.core.exceptions import PermissionDenied
from django.http import HttpResponse

from dbmi_client.settings import dbmi_settings
from dbmi_client import authn
from dbmi_client import authz

# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


def unauthorized_response(request):
    """
    This method is used to return a response in the event a user is not
    authenticated. This differentiates normal HTTP calls from AJAX and
    formats the response accordingly.

    :param request: The current HttpRequest
    :type request: HttpRequest
    :returns: The HttpResponse for the unauthorized call
    :rtype: HttpResponse
    """
    # If AJAX, return unauthorized
    if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':

        # Return unauthorized and put login URL in headers
        response = HttpResponse('401 Unauthorized', status=401)

        # Get the next URL
        next_url = request.build_absolute_uri()

        # If the request was not a GET, redirect back to referrer
        if request.method not in ['HEAD', 'GET']:
            next_url = request.META.get('HTTP_REFERER', next_url)
        response['X-DBMI-LOGIN-URL'] = authn.login_redirect_url(request)

        # Log it
        logger.debug(f"DBMI/Auth: Unauthorized AJAX, next URL: {next_url}")
        response['X-DBMI-LOGIN-URL'] = authn.login_redirect_url(request, next_url)

        return response

    return authn.login_redirect(request)


def dbmi_user(view):
    """
    Decorator to only check if the current user's JWT is valid
    :param function:
    :type function:
    :return:
    :rtype:
    """

    def wrap(request, *args, **kwargs):

        # Check for current user
        if not request.user or not request.user.is_authenticated:
            return unauthorized_response(request)

        # Let it go
        return view(request, *args, **kwargs)

    return wrap


def dbmi_admin(view):
    """
    Decorator to check for valid JWT and admin permissions
    :param function:
    :type function:
    :return:
    :rtype:
    """

    def wrap(request, *args, **kwargs):

        # Check for current user
        if not request.user or not request.user.is_authenticated:
            return unauthorized_response(request)

        # Get the payload
        payload = authn.get_jwt_payload(request, verify=False)

        # Check claims in the JWT first, as it is least costly.
        if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, dbmi_settings.AUTHZ_ADMIN_GROUP):
            return view(request, *args, **kwargs)

        # Get their email address
        email = authn.get_jwt_email(request, verify=False)

        # Now consult the AuthZ server
        if authz.has_permission(request, email, dbmi_settings.CLIENT, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
            return view(request, *args, **kwargs)

        # Possibly store these elsewhere for records
        # TODO: Figure out a better way to flag failed access attempts
        logger.warning(
            "{} Failed {} permission on {}".format(email, dbmi_settings.AUTHZ_ADMIN_PERMISSION, dbmi_settings.CLIENT)
        )

        raise PermissionDenied

    return wrap


def dbmi_group(group):
    """
    Decorator that accepts a group and checks the request user to see if they
    belong to said group.
    :param group: The group
    :type group: str
    :return: function
    """

    def real_decorator(view):
        def wrap(request, *args, **kwargs):

            # Check for current user
            if not request.user or not request.user.is_authenticated:
                return unauthorized_response(request)

            # Get the payload
            payload = authn.get_jwt_payload(request, verify=False)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, group):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning("{} Failed {} group on {}".format(payload.get("email"), group, dbmi_settings.CLIENT))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_role(role):
    """
    Decorator that accepts an item string that is used to retrieve
    roles from JWT AuthZ claims.
    :param role: The role
    :type role: str
    :return: function
    """

    def real_decorator(view):
        def wrap(request, *args, **kwargs):

            # Check for current user
            if not request.user or not request.user.is_authenticated:
                return unauthorized_response(request)

            # Get the payload
            payload = authn.get_jwt_payload(request, verify=False)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_ROLES, role):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning("{} Failed {} group on {}".format(payload.get("email"), role, dbmi_settings.CLIENT))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_app_permission(permission):
    """
    Decorator that accepts an item string that is used to retrieve
    permissions from SciAuthZ.
    :param permission: The permission
    :type permission: str
    :return: function
    """

    def real_decorator(view):
        def wrap(request, *args, **kwargs):

            # Check for current user
            if not request.user or not request.user.is_authenticated:
                return unauthorized_response(request)

            # Get the payload
            payload = authn.get_jwt_payload(request, verify=False)

            # Check claims in the JWT first, as it is least costly.
            if authz.jwt_has_authz(payload, authz.JWT_AUTHZ_PERMISSIONS, permission):
                return view(request, *args, **kwargs)

            # Get their email address
            email = authn.get_jwt_email(request, verify=False)

            # Check permission on the app
            if authz.has_permission(request, email, dbmi_settings.CLIENT, permission):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning("{} Failed {} permission on {}".format(email, permission, dbmi_settings.CLIENT))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator


def dbmi_item_permission(item, permission):
    """
    Decorator that accepts an item string that is checked for the passed permission. Item is an arbitrary
    string the application uses internally for specific or object-level permissions.
    :param item: The item
    :type item: str
    :param permission: The permission
    :type permission: str
    :return: function
    """

    def real_decorator(view):
        def wrap(request, *args, **kwargs):

            # Check for current user
            if not request.user or not request.user.is_authenticated:
                return unauthorized_response(request)

            # Get their email address
            email = authn.get_jwt_email(request, verify=False)

            # Check permission
            if authz.has_permission(request, email, item, permission):
                return view(request, *args, **kwargs)

            # Possibly store these elsewhere for records
            # TODO: Figure out a better way to flag failed access attempts
            logger.warning("{} Failed {} permission on {}".format(email, permission, dbmi_settings.CLIENT))

            # Forbid if nothing else
            raise PermissionDenied

        wrap.__doc__ = view.__doc__
        wrap.__name__ = view.__name__
        return wrap

    return real_decorator
