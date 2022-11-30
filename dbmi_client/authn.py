import jwt
from furl import furl
import json
import base64
from jwt import PyJWKClient
from datetime import datetime, timedelta

from django.apps import apps
from django.contrib import auth as django_auth
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from dbmi_client.settings import dbmi_settings
from dbmi_client import authz
from dbmi_client.serializers import UserSerializer

# Get the app logger
import logging

logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


# Set a key to cache JWKs under in the DBMI.AUTH0 settings
CACHED_JWKS_KEY = "__DBMI_CLIENT_CACHED_JWKS__"

# Set the name of the cookie for testing cookies
DBMI_TEST_COOKIE_NAME = "DBMI_TEST_COOKIE"


def login(request):
    """
    Builds and returns a redirect response to allow the user to login and send them to the
    supplied URL when successfully logged in. If not defined in LOGIN_REDIRECT_URL, the
    current URL in the request will be used, so the user will return to the original location.
    :param request: The original request object
    :return: The redirect response
    """
    return login_redirect(request)


def login_redirect(request, next_url=None):
    """
    Builds and returns a redirect response to allow the user to login and send them to the
    supplied URL when successfully logged in. If next_url is not passed, and
    it is not defined in LOGIN_REDIRECT_URL, the current URL in the request will be used,
    so the user will return to the original location.
    :param request: The original request object
    :param next_url: The URL users will be sent after login
    :return: Response
    """

    # Ensure the request is cleared of user state
    django_auth.logout(request)

    # Get the url
    login_url = login_redirect_url(request, next_url)

    # Just process the logout and redirect them
    response = redirect(login_url)

    # Set a test cookie
    set_login_test_cookie(request, response)

    # Do needed logout functions and return the modified response
    return response


def set_login_test_cookie(request, response):
    """
    Builds and sets a cookie on the current response to enable the authentication
    service to verify whether the user has cookies enabled or not.
    :param request: The original request object
    :type request: HttpRequest
    :param response: The to-be-returned response object
    :type response: HttpResponse
    """
    # Set a date in the future
    date = datetime.now() + timedelta(minutes=10)

    # Set a test cookie
    response.set_cookie(
        DBMI_TEST_COOKIE_NAME,
        date.strftime("%d-%m-%Y %H:%M:%S"),
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )


def verify_login_test_cookie(request):
    """
    Checks for the test cookie in the current request and returns whether the
    test was successful or not.
    :param request: The original request object
    :type request: HttpRequest
    :returns: Whether the test cookie was a success or not
    :rtype: bool
    """
    # Get the test cookie
    value = request.COOKIES.get(DBMI_TEST_COOKIE_NAME)
    if not value:
        logger.info(f"Test cookie was not found, cannot proceed")
        return False

    # Compare date to ensure a recent test
    if datetime.now() >= datetime.strptime(value, "%d-%m-%Y %H:%M:%S"):
        logger.info(f"Test cookie was outdated ({value}), cannot verify cookies")
        return False

    logger.debug(f"Cookie test succeeded")
    return True


def login_redirect_url(request, next_url=None):
    """
    Builds and returns a URL that sends the user to the login, and returns them to the
    supplied URL when successfully logged in. If next_url is not passed, the current URL in the
    request will be used, so the user will return to the original location.
    :param request: The original request object
    :param next_url: The URL users will be sent after login
    :return: Response
    """
    # Check for local login enabled
    if apps.is_installed("dbmi_client.login"):

        # Use local login URL
        login_url = furl(request.build_absolute_uri(reverse("dbmi_login:authorize")))

    else:

        # Build the URL using DBMI-AuthN
        login_url = furl(dbmi_settings.AUTHN_URL)
        login_url.path.segments.extend(["login", "auth"])

    # If no next URL, determine where to dump them after logout
    if not next_url:
        if dbmi_settings.LOGIN_REDIRECT_URL:
            next_url = request.build_absolute_uri(dbmi_settings.LOGIN_REDIRECT_URL)

        else:
            next_url = request.build_absolute_uri()

    # Add next url
    login_url.query.params.add(dbmi_settings.LOGIN_REDIRECT_KEY, next_url)
    logger.debug(f"Login next URL: {next_url}")

    # Add the default client ID
    client_id = next(iter(dbmi_settings.AUTH_CLIENTS.keys()))
    login_url.query.params.add("client_id", client_id)
    logger.debug(f"Auth client ID: {client_id}")

    # Check for branding
    if dbmi_settings.AUTHN_TITLE or dbmi_settings.AUTHN_ICON_URL:

        # Add the included parameters
        branding = {}
        if dbmi_settings.AUTHN_TITLE:
            branding["title"] = dbmi_settings.AUTHN_TITLE

        if dbmi_settings.AUTHN_TITLE:
            branding["icon_url"] = dbmi_settings.AUTHN_ICON_URL

        if dbmi_settings.AUTHN_COLOR:
            branding["color"] = dbmi_settings.AUTHN_COLOR

        if dbmi_settings.AUTHN_BACKGROUND:
            branding["background"] = dbmi_settings.AUTHN_BACKGROUND

        # Encode it and pass it along
        branding_param = base64.urlsafe_b64encode(json.dumps(branding).encode("utf-8")).decode("utf-8")
        login_url.query.params.add("branding", branding_param)

    logger.debug("Login URL: {}".format(login_url.url))
    return login_url.url


def logout(request):
    """
    This will prepare the redirect to log the user out (either internally or at DBMI-AuthN)
    :param request: The Django request object
    :return: The response object that takes the user to the logout endpoint
    """
    # Call logout redirect
    return logout_redirect(request)


def logout_redirect(request, next_url=None):
    """
    This is just an alias for `logout` to support older clients
    """
    # Ensure the request is cleared of user state
    django_auth.logout(request)

    # Build the logout URL
    logout_url = logout_redirect_url(request, next_url)

    # Just process the logout and redirect them
    response = redirect(logout_url)

    # Do needed logout functions and return the modified response
    return response


def logout_redirect_url(request, next_url=None):
    """
    This will prepare the redirect URL to log the user out (either internally or at DBMI-AuthN)
    :param request: The Django request object
    :param next_url: A URL that the user should be sent to should they log back in
    :return: The response object that takes the user to the logout endpoint
    """
    # Check for local login enabled
    if apps.is_installed("dbmi_client.login"):

        # Build the URL to DBMI-Client's logout page
        logout_url = furl(request.build_absolute_uri(reverse("dbmi_login:logout")))

    else:

        # Build the URL to DBMI-AuthN's logout endpoint
        logout_url = furl(dbmi_settings.AUTHN_URL)
        logout_url.path.segments.extend(["login", "logout"])

    # If no next URL, determine where to dump them after logout
    if not next_url:
        if dbmi_settings.LOGOUT_REDIRECT_URL:
            next_url = request.build_absolute_uri(dbmi_settings.LOGOUT_REDIRECT_URL)

        else:
            next_url = request.build_absolute_uri()

    logger.debug("Logout next URL: {}".format(next_url))

    # Add next url
    logout_url.query.params.add(dbmi_settings.LOGOUT_REDIRECT_KEY, next_url)

    # Add the default client ID for the current JWT
    logout_url.query.params.add("client_id", get_jwt_client_id(request, verify=False))

    # Check for branding
    if dbmi_settings.AUTHN_TITLE or dbmi_settings.AUTHN_ICON_URL:

        # Add the included parameters
        branding = {}
        if dbmi_settings.AUTHN_TITLE:
            branding["title"] = dbmi_settings.AUTHN_TITLE

        if dbmi_settings.AUTHN_TITLE:
            branding["icon_url"] = dbmi_settings.AUTHN_ICON_URL

        # Encode it and pass it along
        branding_param = base64.urlsafe_b64encode(json.dumps(branding).encode("utf-8")).decode("utf-8")
        logout_url.query.params.add("branding", branding_param)

    logger.debug("Logout URL: {}".format(logout_url.url))
    return logout_url.url


def dbmi_http_headers(request, content_type="application/json", **kwargs):
    """
    Returns headers to be used for API calls to DBMI services in order to authenticate the caller
    :param request: The Django request
    :param content_type: The content type for the call
    :return: dict
    """

    # Get the JWT
    token = get_jwt(request)

    # Return headers
    headers = {"Authorization": "{}{}".format(dbmi_settings.JWT_HTTP_PREFIX, token), "Content-Type": content_type}

    # Add any additional parameters
    headers.update(kwargs)

    return headers


def get_jwt(request):
    """
    Takes a Django request and pulls the JWT from either cookies or HTTP headers

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :returns: The JWT string
    :rtype: str
    """
    # Get the JWT token depending on request type
    if hasattr(request, "COOKIES") and request.COOKIES.get(dbmi_settings.JWT_COOKIE_NAME):
        return request.COOKIES.get(dbmi_settings.JWT_COOKIE_NAME)

    # Check if JWT in HTTP Authorization header
    elif (
        hasattr(request, "META")
        and request.META.get("HTTP_AUTHORIZATION")
        and dbmi_settings.JWT_HTTP_PREFIX in request.META.get("HTTP_AUTHORIZATION")
    ):

        # Remove prefix and return the token
        return request.META.get("HTTP_AUTHORIZATION").replace(dbmi_settings.JWT_HTTP_PREFIX, "")

    return None


def get_jwt_payload(request, verify=True):
    """
    Returns the payload from the current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The JWT payload
    :rtype: dict
    """
    # Get the JWT token depending on request type
    token = get_jwt(request)

    # Ensure we have a token
    if not token:
        return None

    # Get the payload email
    if not verify:
        try:
            return jwt.decode(
                token,
                algorithms=["RS256", "HS256"],
                options={
                    "verify_signature": False,
                },
                audience=list(dbmi_settings.AUTH_CLIENTS.keys()),
            )

        except jwt.InvalidAudienceError:
            logger.warning(f"No configuration for aud/client ID in token")
            return None
    else:
        return validate_request(request)


def get_jwt_value(request, key, verify=True):
    """
    Returns the value for the passed key from the current JWT payload

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param key: The key of the value in the JWT payload to return
    :type key: str
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The value for the passed key
    :rtype: str
    """
    # Get the payload from above
    payload = get_jwt_payload(request, verify)
    if not payload:
        logger.debug("JWT is invalid, cannot fetch values")
        return None

    return payload.get(key)


def get_jwt_algorithm(request):
    """
    Returns the algorithm that was used to sign current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The name of the algorithm, lowercase
    :rtype: str
    """
    token = get_jwt(request)
    if not token:
        logger.debug("Could not retrieve JWT")
        return None

    return jwt.get_unverified_header(token)["alg"]



def get_jwt_username(request, verify=True):
    """
    Returns the username of the current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The current user's username
    :rtype: str
    """
    return get_jwt_value(request, "sub", verify)


def get_jwt_email(request, verify=True):
    """
    Returns the user email of the current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The current user's email
    :rtype: str
    """
    return get_jwt_value(request, "email", verify)


def get_jwt_client_id(request, verify=True):
    """
    Returns the client ID of the application used to sign current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The client ID of the JWT
    :rtype: str
    """
    return get_jwt_value(request, "aud", verify)


def get_jwt_auth_provider(request, verify=True):
    """
    Returns the provider of the application used to sign current JWT

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :param verify: Whether to verify the JWT signature first
    :type verify: bool
    :returns: The provider of the current authentication provider
    :rtype: str
    """
    iss = get_jwt_value(request, "iss", verify)

    # Check URLs
    if iss.lower().contains("auth0.com"):
        return "auth0"
    elif iss.lower().contains("amazonaws.com"):
        return "cognito"


def validate_request(request):
    """
    Pulls the current cookie and verifies the JWT and
    then returns the JWT payload. Returns None
    if the JWT is invalid or missing.

    :param request: The current HttpRequest object
    :type request: HttpRequest
    :returns: The verified JWT payload
    :rtype: dict
    """
    # Extract JWT from request.
    token = get_jwt(request)

    # Get the payload
    payload = get_jwt_payload(request, verify=False)

    # Get client ID
    client_id = get_jwt_client_id(request, verify=False)

    # Fetch key based off algorithm
    algorithm = get_jwt_algorithm(request)
    if algorithm == "RS256":

        # Match the client ID to an authentication provider
        url = dbmi_settings.AUTH_CLIENTS[client_id]["JWKS_URL"]
        jwks_client = PyJWKClient(
            url,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=86400,
        )
        key = jwks_client.get_signing_key_from_jwt(token).key

    elif algorithm == "HS256":

        # Fetch key from auth configuration
        key = dbmi_settings.AUTH_CLIENTS[client_id]["CLIENT_SECRET"]

    else:
        logger.warning(f"Unsupported algorithm for token: {algorithm}")
        return None

    try:
        # Perform the validation
        payload = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            leeway=120,
            audience=client_id,
        )

        return payload

    except jwt.ExpiredSignatureError as e:
        logger.debug(
            f"JWT Expired: {e}",
        )

    except jwt.InvalidTokenError as e:
        logger.info(
            f"Invalid JWT Token: {e}",
        )

    except Exception as e:
        logger.exception(
            f"Error validating JWT: {e}",
            exc_info=True,
            extra={
                "client_id": client_id,
            },
        )

    return None

###################################################################
#
# Django Custom Authentication Backends
#
###################################################################


class DBMIAuthenticationBackend(object):
    def authenticate(self, request, token=None):
        """
        All versions of this backend follow the same flow:
        1. Check JWT is present
        2. Check JWT validity
        3. Check JWT payload for required user properties
        4. Return existing user or create new one
        5. Sync user, if already exists, with JWT payload
        """
        # Get the token
        if not token:
            token = get_jwt(request)
            if not token:
                return None

        # Validate request
        payload = validate_request(request)
        if not payload:
            return None

        # Get their email and check for their record
        email = payload.get("email")
        username = payload.get("sub")
        if not email or not username:
            logger.error("No sub or email in valid JWT: {}".format(payload))
            return None

        # The JWT is valid, now get the user object to attach to the request
        user = self._get_user_object(request)
        if not user:

            # Create the user, which will also sync
            user = self._create_user(request)

        else:

            # Sync the user to ensure we've got updated properties
            self._sync_user(request, user)

        return user

    def get_user(self, user_id):
        # Should be implemented by subclass depending on data source for user
        raise SystemError("This method should not be called")

    def has_perm(self, user, perm, obj):
        """
        Returns whether the given user has the permission or not
        """
        # This authentication backend does not manage Django-style permissions
        pass

    def has_module_perms(self, user, app_label):
        """
        Returns whether the given user has permissions on the module or not
        """
        # This authentication backend does not manage Django-style permissions
        pass

    def _get_user_object(self, request):
        """
        Accepts details from the JWT user and returns an object representing
        the request's user. If model is enabled, this will be an instance of User,
        otherwise an instance of DBMIUser
        """
        # Should be implemented by subclass depending on data source for user
        raise SystemError("This method should not be called")

    def _create_user(self, request):
        """
        Called when a user in the model does not exist. This creates the user in the
        model.
        """
        # Should be implemented by subclass depending on data source for user
        raise SystemError("This method should not be called")

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        username = None
        email = None
        try:
            # Get the unverified payload
            payload = get_jwt_payload(request, verify=False)

            # Get properties
            username = payload["sub"].lower()
            email = payload["email"].lower()

            # Check if email or username missing
            if not user.username.lower() == username:
                logger.debug("User's username did not match JWT: {} -> {}".format(user.username, username))
                user.username = username

            if not user.email.lower() == email:
                logger.error(
                    "User's email did not match JWT: {} -> {}".format(user.email, email),
                    extra={
                        "request": request,
                        "username": user.username,
                        "email": user.email,
                        "jwt_username": username,
                        "jwt_email": email,
                    },
                )
                raise PermissionDenied

        except Exception as e:
            logger.exception(
                "User syncing error: {}".format(e),
                exc_info=True,
                extra={"request": request, "user": user, "username": username, "email": email},
            )


class DBMIJWTAuthenticationBackend(DBMIAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies).
    Users objects are an instance of DBMIJWTUser and mimic the properties and methods of Django's built-in
    contrib.auth.models.User model, but with no persistence. All properties will be valid but any attempt to
    save or link these instances to another model instance will fail.
    """

    def _get_user_object(self, request):
        """
        Accepts details from the JWT user and returns an object representing
        the request's user.
        """
        # Create an instance of the JWT user
        user = DBMIJWTUser(request)

        # Sync their profile and return them
        self._sync_user(request, user)

        return user

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        # The user object is built from the JWT on every request so syncing is redundant and
        # not required.
        pass


class DBMIJWTAdminAuthenticationBackend(DBMIAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies).
    Users objects are an instance of DBMIJWTUser and mimic the properties and methods of Django's built-in
    contrib.auth.models.User model, but with no persistence. All properties will be valid but any attempt to
    save or link these instances to another model instance will fail. DBMI AuthZ is consulted for staff/superuser
    access and the User object is prepared as such.
    """

    def _get_user_object(self, request):
        """
        Accepts details from the JWT user and returns an object representing
        the request's user.
        """
        # Create an instance of the JWT user
        user = DBMIJWTUser(request)

        # Sync their profile and return them
        self._sync_user(request, user)

        return user

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        # All sync admin/superuser status
        try:
            # Check if admin/superuser
            if authz.is_admin(request, user.email):
                user.is_staff = True
                user.is_superuser = True
            else:
                user.is_staff = False
                user.is_superuser = False

        except Exception as e:
            logger.exception(
                "User syncing error: {}".format(e), exc_info=True, extra={"user": user, "request": request}
            )


class DBMIModelAuthenticationBackend(DBMIAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies).
    If enabled, users are auto-created upon first attempted login with a valid JWT. The
    User model is keyed by the username and email contained in the JWT. Profile and groups are synced
    from the JWT upon each login.
    """

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        is_active = getattr(user, "is_active", None)
        return is_active or is_active is None

    def get_user(self, user_id):
        UserModel = django_auth.get_user_model()
        try:
            user = UserModel._default_manager.get(pk=user_id)

        except UserModel.DoesNotExist:
            return None

        return user if self.user_can_authenticate(user) else None

    def _get_user_object(self, request):
        """
        Accepts details from the JWT user and returns an object representing
        the request's user. If model is enabled, this will be an instance of User,
        otherwise an instance of DBMIUser
        """
        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Fetch the current User model
        UserModel = django_auth.get_user_model()

        # Find the user
        users = UserModel.objects.filter(Q(username=username) | Q(email=email)).order_by("-date_joined")
        if not users:
            logger.debug("User does not yet exist: {} : {}".format(username, email))
            return None

        # Get first user
        user = users.first()

        # Check for duplicate users (on email)
        if len(users) > 1:
            logger.error(
                "Found {} users for {} : {}".format(len(users), email, ",".join([u.username for u in users])),
                extra={"request": request, "users": json.dumps(UserSerializer(users, many=True).data)},
            )
            logger.debug("Returning oldest user: {} : {}".format(user.username, user.email))

        else:
            logger.debug("Found user: {} : {}".format(username, email))

        return user

    def _create_user(self, request):
        """
        Called when a user in the model does not exist. This creates the user in the
        model.
        """
        # Check if autocreate is enabled
        if not dbmi_settings.USER_MODEL_AUTOCREATE:
            logger.debug("User autocreate is disabled, boot the current user")
            raise PermissionDenied

        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Create them
        UserModel = django_auth.get_user_model()
        user = UserModel(username=username, email=email)
        user.set_unusable_password()
        logger.debug("Created user: {}:{}".format(username, email))

        # Sync them up
        self._sync_user(request, user)

        return user

    def _set_superuser(self, request, user):
        """
        This method allows backends to determine whether or not an admin user
        should be granted Django superuser status.

        :param request: The current request
        :type request: HttpRequest
        :param user: The current user
        :type user: User
        """
        return False

    def _set_staff(self, request, user):
        """
        This method allows backends to determine whether or not an admin user
        should be granted Django superuser status.

        :param request: The current request
        :type request: HttpRequest
        :param user: The current user
        :type user: User
        """
        return False

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        username = None
        email = None
        try:
            # Get the unverified payload
            payload = get_jwt_payload(request, verify=False)

            # Get properties
            username = payload["sub"].lower()
            email = payload["email"].lower()

            # Check if email or username missing
            if not user.username.lower() == username:
                logger.debug("User's username did not match JWT: {} -> {}".format(user.username, username))
                user.username = username

            if not user.email.lower() == email:
                logger.error(
                    "User's email did not match JWT: {} -> {}".format(user.email, email),
                    extra={
                        "request": request,
                        "username": user.username,
                        "email": user.email,
                        "jwt_username": username,
                        "jwt_email": email,
                    },
                )
                raise PermissionDenied

            # Check if superuser/staff
            if self._set_staff(request, user):
                user.is_staff = True

            if self._set_superuser(request, user):
                user.is_superuser = True

            # Save
            user.save()

        except Exception as e:
            logger.exception(
                "User syncing error: {}".format(e),
                exc_info=True,
                extra={"request": request, "user": user, "username": username, "email": email},
            )


class DBMIUsersModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies).
    Use this authentication backend for sites that are accessible to all users as well as administrator users.
    User model is keyed by the username and email contained in the JWT. `is_staff` and `is_superuser` flags
    are automatically set and synced on appropriate users. Every active user with admin authorization on this site
    will have complete access to everything.
    """

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object. Set staff and superuser flags
        if authorizations are valid.
        """
        # Do normal sync first
        super(DBMIModelAuthenticationBackend, self)._sync_user(request, user)

        is_admin = False
        try:
            # Check if admin
            is_admin = authz.is_admin(request, user.email)
            if is_admin:
                logger.debug(f"User: {user.email} has been granted admin/superuser privileges")

            # Ensure the model is updated
            user.is_staff = is_admin
            user.is_superuser = is_admin
            user.save()

        except Exception as e:
            logger.exception(
                "Superuser syncing error: {}".format(e),
                exc_info=True,
                extra={
                    "request": request,
                    "user": user,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": is_admin,
                },
            )


class DBMIRestrictedModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    A method performs an inspection of any proposed users' authorizations and permissions and determines
    if they should be created within the model or not. The default implementation requires proposed
    users to have any existing permissions on the current application.

    Use this authentication backend for sites that are only accessible to users with specific
    permissions/roles/groups. User model is keyed by the username and email contained in the JWT.
    Profile and groups are synced from the JWT upon each login.
    """

    def _should_create_user(self, request, email):
        """
        This method inspects the proposed user and returns whether they should be created or not.
        Typically, before a user is rejected due to a missing permission, their record will have
        already been created in the Django model. This method allows subclassing backends to do
        a check of the proposed user before the creation step, thus avoiding User entries that
        would never be able to log in anyways. The default implementation checks for any existing
        permissions on the current application.

        :param request: The current request
        :type request: HttpRequest
        :param email: The email of the requesting user
        :type email: str
        :return: Whether the user should be created or not
        :rtype: bool
    """
        return len(authz.get_permissions(request, email, item=dbmi_settings.CLIENT, children=True)) > 1

    def _create_user(self, request):
        """
        This middleware performs exactly like its superclass, with the exception of checking
        an authenticated user's authorizations before creating them in the model. This would
        be used for sites where only admins/superusers/staff should have access.
        """
        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Before we create a user, we must ensure they have authorizations
        if not self._should_create_user(request, email):
            logger.debug('User {}/{} did not pass restriction test, access denied'.format(username, email))
            raise PermissionDenied

        # Create them
        UserModel = django_auth.get_user_model()
        user = UserModel(username=username, email=email)
        user.set_unusable_password()
        logger.debug("Created user: {}:{}".format(username, email))

        # Sync them up
        self._sync_user(request, user, is_admin=True)

        return user

    def _sync_user(self, request, user, is_admin=None):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object. This method is extended to
        add the flag determining admin authorization to prevent multiple
        requests to the authz server.
        """
        # Do normal sync first
        super(DBMIRestrictedModelAuthenticationBackend, self)._sync_user(request, user)


class DBMIAdminModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    A method performs an inspection of any proposed users' authorizations and permissions and determines
    if they should be created within the model or not. The default implementation requires proposed
    users to have an 'admin' permission set on the current app, but can be overidden to check for
    other authorizations.

    Use this authentication backend for sites that are only accessible to users with specific
    permissions/roles/groups. User model is keyed by the username and email contained in the JWT.
    Profile and groups are synced from the JWT upon each login.
    """

    def _should_create_user(self, request, email):
        """
        This method inspects the proposed user and returns whether they should be created or not.
        Typically, before a user is rejected due to a missing permission, their record will have
        already been created in the Django model. This method allows subclassing backends to do
        a check of the proposed user before the creation step, thus avoiding User entries that
        would never be able to log in anyways. The default implementation checks for a single
        'admin' permission on the current application.

        :param request: The current request
        :type request: HttpRequest
        :param email: The email of the requesting user
        :type email: str
        :return: Whether the user should be created or not
        :rtype: bool
        """
        return authz.is_admin(request, email)


class DBMISuperuserModelAuthenticationBackend(DBMIAdminModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as admin authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    Use this authentication backend for sites that are only accessible to admins and no other users.
    User model is keyed by the username and email contained in the JWT. `is_staff` and `is_superuser` flags
    are automatically set and synced on users. Every active user with authorization on this site
    will have complete access to everything.
    """

    def _sync_user(self, request, user, is_admin=None):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object. Set staff and superuser flags
        if authorizations are valid.
        """
        # Do normal sync first
        super(DBMISuperuserModelAuthenticationBackend, self)._sync_user(request, user)

        try:
            # Check if admin
            if is_admin is None:
                is_admin = authz.is_admin(request, user.email)

            # Ensure the model is updated
            user.is_staff = is_admin
            user.is_superuser = is_admin
            user.save()

            # If not admin (indicates they used to be), save and raise exception
            if not is_admin:
                logger.debug("User was superuser, but is now missing authz, booting them: {}".format(user.username))
                raise PermissionDenied

        except Exception as e:
            logger.exception(
                "Superuser syncing error: {}".format(e),
                exc_info=True,
                extra={
                    "request": request,
                    "user": user,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": is_admin,
                },
            )

            logger.debug("Encountered an issue and could not check admin/superuser status: defaulting to access denied")
            raise PermissionDenied


###################################################################
#
# Django user object for user-less databases
#
###################################################################


class DBMIJWTUser(AnonymousUser):
    """
    This class represents a JWT user for an application that does not persist those
    users to the store. It provides a request.user object to access user properties
    but will throw exceptions if ever used in the context of database operations.
    """

    email = None
    username = None
    id = None
    pk = None
    is_active = True
    is_staff = False
    is_superuser = False
    jwt = None

    def __init__(self, request):

        # Get the payload
        payload = get_jwt_payload(request, verify=False)
        self.jwt = get_jwt(request)

        # Set properties
        self.username = payload.get("sub")
        self.id = payload.get("sub")
        self.email = payload.get("email")

    def __str__(self):
        return self.id

    def __eq__(self, other):
        return hasattr(other, "id") and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    def save(self):
        raise NotImplementedError("Django doesn't provide a DB representation for DBMIJWTUser.")

    def delete(self):
        raise NotImplementedError("Django doesn't provide a DB representation for DBMIJWTUser.")

    def set_password(self, raw_password):
        raise NotImplementedError("Django doesn't provide a DB representation for DBMIJWTUser.")

    def check_password(self, raw_password):
        raise NotImplementedError("Django doesn't provide a DB representation for DBMIJWTUser.")

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    def get_username(self):
        return self.username

    def get_group_permissions(self, obj=None):
        """
        Return a list of permission strings that this user has through their
        groups. Query all available auth backends. If an object is passed in,
        return only permissions matching this object.
        """
        permissions = set()
        return permissions

    def get_all_permissions(self, obj=None):
        # Get permissions from AuthZ
        return authz.get_permissions(self.jwt, self.email, obj)

    def has_perm(self, perm, obj=None):
        """
        Return True if the user has the specified permission. Query all
        available auth backends, but return immediately if any backend returns
        True. Thus, a user who has permission from a single auth backend is
        assumed to have permission in general. If an object is provided, check
        permissions for that object.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Return True if the user has each of the specified permissions. If
        object is passed, check if the user has all required perms for it.
        """
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label):
        """
        Return True if the user has any permissions in the given app label.
        Use similar logic as has_perm(), above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)


def _user_has_perm(user, perm, obj):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in django_auth.get_backends():
        if not hasattr(backend, "has_perm"):
            continue
        try:
            if backend.has_perm(user, perm, obj):
                return True
        except PermissionDenied:
            return False
    return False


def _user_has_module_perms(user, app_label):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in django_auth.get_backends():
        if not hasattr(backend, "has_module_perms"):
            continue
        try:
            if backend.has_module_perms(user, app_label):
                return True
        except PermissionDenied:
            return False
    return False


###################################################################
#
# Django Rest Framework (DRF) Custom Authentication/Authorization
#
###################################################################


class DBMIUser(BaseAuthentication):
    """
    Authentication method for DBMI API methods
    """

    def authenticate(self, request):

        # Get the JWT
        token = get_jwt(request)
        if not token:
            raise exceptions.NotAuthenticated

        # User has a valid JWT from SciAuth
        payload = validate_request(request)
        if not payload:
            raise exceptions.AuthenticationFailed

        # Return the user's email to attach to the request object (request.user)
        # Also, return the authz dictionary contained in the JWT claims, if present (request.auth)
        return payload.get("email"), payload.get(dbmi_settings.JWT_AUTHZ_NAMESPACE)


class DBMIModelUser(BaseAuthentication):
    """
    Authentication method for DBMI API methods
    """

    def authenticate(self, request):

        # Get the JWT
        token = get_jwt(request)
        if not token:
            raise exceptions.NotAuthenticated

        # Call the standard Django authenticate method, that will in
        # turn call DBMIModelAuthenticationBackend.authenticate
        user = django_auth.authenticate(request, token=token)
        if not user:
            raise exceptions.AuthenticationFailed

        # Check if JWT contains AuthZ
        auth = None
        if dbmi_settings.JWT_AUTHZ_NAMESPACE:

            # User has a valid JWT from SciAuth
            auth = get_jwt_payload(request, verify=False).get("JWT_AUTHZ_NAMESPACE")

        # Return the user's email to attach to the request object (request.user)
        # Also, return the authz dictionary contained in the JWT claims, if present (request.auth)
        return user, auth
