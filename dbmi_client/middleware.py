from django.contrib import auth as django_auth
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.utils.functional import SimpleLazyObject
from django.utils.deprecation import MiddlewareMixin

from dbmi_client.settings import dbmi_settings
from dbmi_client import authn

# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


class DBMIAuthenticationMiddleware(MiddlewareMixin):
    """
    Before loading cached user objects, we want to double-check the JWT to:
    1. Ensure it exists still
    2. Ensure it belongs to the currently cached user
    If any of the above do not pass, do the logout routine

    This middleware is a hybrid of purely JWT authentication and session authentication. The
    initial authentication is performed by inspecting the JWT and then loading/creating the user.
    That user's pk is cached exactly how normal session auth works, and is then consulted from there
    on out to load that user to each request. Once the session expires, the JWT is then looked at
    again to provide authentication. Also, the JWT is still consulted on every request to make sure
    the current user is matched to the current JWT. This check is simply comparing the JWT username/email
    to that of the user instance. If a user session exists and the JWT was swapped for some reason,
    this will detect that change and invalidate the current user session and require another initial
    authentication process.

    When you would use this middleware: This is ideal for instances in which the authentication process
    does some heavy or involved work. If authenticating depends on requests being made to the authorization
    server or resources being pulled from remote sources, this work would be done for every single request,
    and would not be ideal. Doing it upon first auth, and then using the session to determine if the user
    is current or not, minimizes that work, but still ensures JWT defines authentication state.
    """

    def process_request(self, request):
        request.user = SimpleLazyObject(lambda: self.__class__.get_jwt_user(request))

    @staticmethod
    def get_jwt_user(request):

        # Check for a valid token
        token = authn.get_jwt(request)
        if not token or not authn.validate_rs256_jwt(token):
            return AnonymousUser()

        # Get their username
        username = authn.get_jwt_username(request, verify=False)

        # Use the usual routine to get the currently cached user
        user = django_auth.get_user(request)
        if user.is_authenticated:
            logger.debug('Found existing User session: {}'.format(username))

            # A cached user is present. We need to double-check JWT user to ensure
            # they are the same as the cached user.
            username = authn.get_jwt_username(request, verify=False)
            email = authn.get_jwt_email(request, verify=False)
            if username and email:
                if not user.username.lower() == username.lower() or not user.email.lower() == email.lower():
                    logger.debug('User session does not match JWT, logging out')

                    # TODO: Figure out if its necessary to person any session invalidation here
                    return AnonymousUser()

        else:
            logger.debug('No existing User, attempting to login: {}'.format(username))

            # No user is logged in but we have a JWT token. Attempt to authenticate
            # the current JWT and if it succeeds, login and cache the user.
            user = django_auth.authenticate(request, token=token)
            if user and user.is_authenticated:
                logger.debug('User has authenticated: {}'.format(username))

                # Store this user in session
                django_auth.login(request, user)

            else:
                logger.debug('User could not be authenticated: {}'.format(username))
                # Whatever token this user has, it's not valid OR their account would/could not
                # be created, deny permission. This will likely be the case for instances where
                # automatic user creation is disabled and a user with a valid JWT is not being
                # granted an account.
                raise PermissionDenied

        return user


class DBMIUsersAuthenticationMiddleware(DBMIAuthenticationMiddleware):
    """
    Before loading cached user objects, we want to double-check the JWT to:
    1. Ensure it exists still
    2. Ensure it belongs to the currently cached user.
    3. If the cached user is an admin, confirm their permissions by re-running login and authorization sync.
    If any of the above do not pass, do the logout routine

    This middleware is a hybrid of purely JWT authentication and session authentication. The
    initial authentication is performed by inspecting the JWT and then loading/creating the user.
    That user's pk is cached exactly how normal session auth works, and is then consulted from there
    on out to load that user to each request. Once the session expires, the JWT is then looked at
    again to provide authentication. Also, the JWT is still consulted on every request to make sure
    the current user is matched to the current JWT. This check is simply comparing the JWT username/email
    to that of the user instance. If a user session exists and the JWT was swapped for some reason,
    this will detect that change and invalidate the current user session and require another initial
    authentication process.

    What sets this middelware apart from `DBMIAuthenticationMiddleware` is admin users are checked
    with every request to ensure permissions are up-to-date. The additional overhead might be considered
    appropriate to ensure changes to administrator permissions are checked with every request to prevent
    a cached user to have elevated permissions after those permissions might have been revoked at the
    authorization server. Normal users are cached and fetched normally and this do not impose the
    additional overhead of double-checking status.

    When you would use this middleware: This is ideal for instances in which the authentication process
    does some heavy or involved work, but admins should be confirmed on every request, no matter what.
    If authenticating depends on requests being made to the authorization server or resources being pulled
    from remote sources, this work would be done for every single request, and would not be ideal. Doing
    it upon first auth, and then using the session to determine if the user is current or not, minimizes
    that work, but still ensures JWT defines authentication state.
    """

    def process_request(self, request):
        request.user = SimpleLazyObject(lambda: self.__class__.get_jwt_user(request))

    @staticmethod
    def get_jwt_user(request):

        # Use super's implementation
        user = super(DBMIUsersAuthenticationMiddleware).get_jwt_user(request)
        if user:

            # Check if they've been granted admin level privileges
            if user.is_staff or user.is_superuser:

                # Get details
                token = authn.get_jwt(request)
                username = authn.get_jwt_username(request, verify=False)
                email = authn.get_jwt_email(request, verify=False)

                logger.debug(f'User "{username}":"{email}" is currently admin; rerunning sync...')

                # Run their sync again to make absolutely sure they're still an admin
                user = django_auth.authenticate(request, token=token)
                if user and user.is_authenticated:
                    logger.debug('User has re-authenticated: {}'.format(username))

                    # Store this user in session
                    django_auth.login(request, user)

                    # Check updated status
                    if user.is_superuser or user.is_staff:
                        logger.debug(f'User "{username}":"{email}" is still admin')

                else:
                    logger.debug('User could not be authenticated: {}'.format(username))
                    # Whatever token this user has, it's not valid OR their account would/could not
                    # be created, deny permission. This will likely be the case for instances where
                    # automatic user creation is disabled and a user with a valid JWT is not being
                    # granted an account.
                    raise PermissionDenied

        return user


class DBMIJWTAuthenticationMiddleware(MiddlewareMixin):
    """
    This middleware does not use any user caching at all. For every request, the JWT, if present, is
    inspected to get the username and/or email and that is used to retrieve and set the user on
    the request object. Instead of caching the user's pk on first authentication and then using that
    to pull the user instance on subsequent requests, this simply authenticates the user on every request.
    Since the session is not used, instances of mismatched session and JWT should not occur. Instead
    of relying on the session to cache the current user, we simply use the JWT to do that.

    When to use this middleware: your site depends on JWT to authenticate and there's nothing heavy about the
    authorization process (syncing user state from other services, fetching authorizations, etc)
    """

    def process_request(self, request):
        request.user = SimpleLazyObject(lambda: self.__class__.get_jwt_user(request))

    @staticmethod
    def get_jwt_user(request):

        # Check for a valid token
        token = authn.get_jwt(request)
        if not token or not authn.validate_rs256_jwt(token):
            return AnonymousUser()

        # Get their username
        username = authn.get_jwt_username(request, verify=False)

        # Attempt to authenticate the current JWT.
        user = django_auth.authenticate(request, token=token)
        if not user or not user.is_authenticated:
            logger.debug('User could not be authenticated: {}'.format(username))
            # Whatever token this user has, it's not valid OR their account would/could not
            # be created, deny permission. This will likely be the case for instances where
            # automatic user creation is disabled and a user with a valid JWT is not being
            # granted an account.
            raise PermissionDenied

        return user
