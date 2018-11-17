import jwt
from furl import furl
import json
import base64
import requests
import jwcrypto.jwk as jwk

from django.contrib import auth as django_auth
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.core.exceptions import MultipleObjectsReturned
from django.shortcuts import redirect
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from dbmi_client.settings import dbmi_settings
from dbmi_client import authz

# Get the app logger
logger = dbmi_settings.get_logger()

# Set a key to cache JWKs under in the DBMI.AUTH0 settings
CACHED_JWKS_KEY = '__DBMI_CLIENT_CACHED_JWKS__'


def login_redirect_url(request, next_url=None):
    """
    Builds and returns a URL that sends the user to the login, and returns them to the
    supplied URL when successfully logged in. If next_url is not passed, the current URL in the
    request will be used, so the user will return to the original location.
    :param request: The original request object
    :param next_url: The URL users will be sent after login
    :return: Response
    """

    # Build the URL
    login_url = furl(dbmi_settings.AUTHN_URL)
    login_url.path.segments.extend(['login', 'auth'])

    # Check for the next URL
    if next_url:
        login_url.query.params.add('next', next_url)

    else:
        login_url.query.params.add('next', request.build_absolute_uri())

    # Check for branding
    if dbmi_settings.AUTHN_TITLE or dbmi_settings.AUTHN_ICON_URL:

        # Add the included parameters
        branding = {}
        if dbmi_settings.AUTHN_TITLE:
            branding['title'] = dbmi_settings.AUTHN_TITLE

        if dbmi_settings.AUTHN_TITLE:
            branding['icon_url'] = dbmi_settings.AUTHN_ICON_URL

        # Encode it and pass it along
        branding_param = base64.urlsafe_b64encode(json.dumps(branding).encode('utf-8')).decode('utf-8')
        login_url.query.params.add('branding', branding_param)

    return login_url.url


def logout_redirect(request):
    """
    This will log a user out and redirect them to log in again via the AuthN server.
    :param request:
    :return: The response object that takes the user to the login page. 'next' parameter set to bring them back to their intended page.
    """
    # Ensure the request is cleared of user state
    django_auth.logout(request)

    # Get a login response
    response = redirect(login_redirect_url(request))

    # Set the URL and purge cookies
    response.delete_cookie(dbmi_settings.JWT_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

    return response


def dbmi_http_headers(request, content_type='application/json', **kwargs):
    """
    Returns headers to be used for API calls to DBMI services in order to authenticate the caller
    :param request: The Django request
    :param content_type: The content type for the call
    :return: dict
    """

    # Get the JWT
    token = get_jwt(request)

    # Return headers
    headers = {'Authorization': '{}{}'.format(dbmi_settings.JWT_HTTP_PREFIX, token), 'Content-Type': content_type}

    # Add any additional parameters
    headers.update(kwargs)

    return headers


def get_jwt(request):
    """
    Takes a Django request and pulls the JWT from either cookies or HTTP headers
    :param request: The Django request
    :return: The JWT, if found
    """
    # Get the JWT token depending on request type
    if hasattr(request, 'COOKIES') and request.COOKIES.get(dbmi_settings.JWT_COOKIE_NAME):
        return request.COOKIES.get(dbmi_settings.JWT_COOKIE_NAME)

    # Check if JWT in HTTP Authorization header
    elif hasattr(request, 'META') and request.META.get('HTTP_AUTHORIZATION') and dbmi_settings.JWT_HTTP_PREFIX \
            in request.META.get('HTTP_AUTHORIZATION'):

        # Remove prefix and return the token
        return request.META.get('HTTP_AUTHORIZATION').replace(dbmi_settings.JWT_HTTP_PREFIX, '')

    return None


def get_jwt_payload(request, verify=True):

    # Get the JWT token depending on request type
    token = get_jwt(request)

    # Get the payload email
    if not verify:
        return jwt.decode(token, verify=False)

    else:
        return validate_rs256_jwt(token)


def get_jwt_value(request, key, verify=True):

    # Get the payload from above
    payload = get_jwt_payload(request, verify)
    if not payload:
        logger.debug('JWT is invalid, cannot fetch values')
        return None

    return payload.get(key)


def get_jwt_username(request, verify=True):
    return get_jwt_value(request, 'sub', verify)


def get_jwt_email(request, verify=True):
    return get_jwt_value(request, 'email', verify)


def validate_request(request):
    '''
    Pulls the current cookie and verifies the JWT and
    then returns the JWT payload. Returns None
    if the JWT is invalid or missing.
    :param request: The Django request object
    :return: dict
    '''

    # Extract JWT token into a string.
    jwt_string = get_jwt(request)

    # Check that we actually have a token.
    if jwt_string is not None:
        return validate_rs256_jwt(jwt_string)
    else:
        return None


def get_public_keys_from_auth0(refresh=False):
    '''
    Retrieves the public key from Auth0 to verify JWTs. Will
    cache the JSON response from Auth0 in Django settings
    until instructed to refresh the JWKS.
    :param refresh: Purges cached JWK and fetches from remote
    :return: dict
    '''

    # If refresh, delete cached key
    if refresh:
        delattr(dbmi_settings, CACHED_JWKS_KEY)

    try:
        # Look in settings
        if hasattr(dbmi_settings, CACHED_JWKS_KEY):
            logger.debug('Using cached JWKS')

            # Parse the cached dict and return it
            return json.loads(getattr(dbmi_settings, CACHED_JWKS_KEY))

        else:

            logger.debug('Fetching remote JWKS')

            # Build the JWKs URL
            url = furl().set(scheme='https', host='{}.auth0.com'.format(dbmi_settings.AUTH0_TENANT))
            url.path.segments.extend(['.well-known', 'jwks.json'])

            # Make the request
            response = requests.get(url.url)
            response.raise_for_status()

            # Parse it
            jwks = response.json()

            # Cache it
            setattr(dbmi_settings, CACHED_JWKS_KEY, json.dumps(jwks))

            return jwks

    except KeyError as e:
        logger.exception(e)

    except json.JSONDecodeError as e:
        logger.exception(e)

    except requests.HTTPError as e:
        logger.exception(e)

    return None


def retrieve_public_key(jwt_string):
    '''
    Gets the public key used to sign the JWT from the public JWK
    hosted on Auth0. Auth0 typically only returns one public key
    in the JWK set but to handle situations in which signing keys
    are being rotated, this method is build to search through
    multiple JWK that could be in the set.

    As JWKS are being cached, if a JWK cannot be found, cached
    JWKS is purged and a new JWKS is fetched from Auth0. The
    fresh JWKS is then searched again for the needed key.

    Returns the key ID if found, otherwise returns None
    :param jwt_string: The JWT token as a string
    :return: str
    '''

    try:
        # Get the JWK
        jwks = get_public_keys_from_auth0(refresh=False)

        # Decode the JWTs header component
        unverified_header = jwt.get_unverified_header(str(jwt_string))

        # Check the JWK for the key the JWT was signed with
        rsa_key = get_rsa_from_jwks(jwks, unverified_header['kid'])
        if not rsa_key:
            logger.debug('No matching key found in JWKS, refreshing')
            logger.debug('Unverified JWT key id: {}'.format(unverified_header['kid']))
            logger.debug('Cached JWK keys: {}'.format([jwk['kid'] for jwk in jwks['keys']]))

            # No match found, refresh the jwks
            jwks = get_public_keys_from_auth0(refresh=True)
            logger.debug('Refreshed JWK keys: {}'.format([jwk['kid'] for jwk in jwks['keys']]))

            # Try it again
            rsa_key = get_rsa_from_jwks(jwks, unverified_header['kid'])
            if not rsa_key:
                logger.error('No matching key found despite refresh, failing')

        return rsa_key

    except KeyError as e:
        logger.debug('Could not compare keys, probably old HS256 session')

    return None


def get_rsa_from_jwks(jwks, jwt_kid):
    '''
    Searches the JWKS for the signing key used
    for the JWT. Returns a dict of the JWK
    properties if found, None otherwise.
    :param jwks: The set of JWKs from Auth0
    :param jwt_kid: The key ID of the signing key
    :return: dict
    '''
    # Build the dict containing rsa values
    for key in jwks["keys"]:
        if key["kid"] == jwt_kid:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

            return rsa_key

    # No matching key found, must refresh JWT keys
    return None


def validate_rs256_jwt(jwt_string):
    '''
    Verifies the given RS256 JWT. Returns the payload
    if verified, otherwise returns None.
    :param jwt_string: JWT as a string
    :return: dict
    '''

    rsa_pub_key = retrieve_public_key(jwt_string)
    if rsa_pub_key:

        # Get the JWK
        jwk_key = jwk.JWK(**rsa_pub_key)

        # Determine which Auth0 Client ID (aud) this JWT pertains to.
        try:
            auth0_client_id = str(jwt.decode(jwt_string, verify=False)['aud'])
        except Exception as e:
            logger.error('Failed to get the aud from jwt payload: {}'.format(e))
            return None

        # Check that the Client ID is in the allowed list of Auth0 Client IDs for this application
        if not auth0_client_id == dbmi_settings.AUTH0_CLIENT_ID:
            logger.error('Auth0 Client ID not allowed')
            return None

        # Attempt to validate the JWT (Checks both expiry and signature)
        try:
            payload = jwt.decode(jwt_string,
                                 jwk_key.export_to_pem(private_key=False),
                                 algorithms=['RS256'],
                                 leeway=120,
                                 audience=auth0_client_id)

            return payload

        except jwt.ExpiredSignatureError as e:
            logger.warning("JWT Expired: {}".format(e))

        except jwt.InvalidTokenError as e:
            logger.warning("Invalid JWT Token: {}".format(e))

        except Exception as e:
            logger.error("Exception: {}".format(e))

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
        payload = validate_rs256_jwt(token)
        if not payload:
            return None

        # Get their email and check for their record
        email = payload.get('email')
        username = payload.get('sub')
        if not email or not username:
            logger.error('No sub or email in valid JWT: {}'.format(payload))
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
        raise SystemError('This method should not be called')

    def _get_user_object(self, request):
        """
        Accepts details from the JWT user and returns an object representing
        the request's user. If model is enabled, this will be an instance of User,
        otherwise an instance of DBMIUser
        """
        # Should be implemented by subclass depending on data source for user
        raise SystemError('This method should not be called')

    def _create_user(self, request):
        """
        Called when a user in the model does not exist. This creates the user in the
        model.
        """
        # Should be implemented by subclass depending on data source for user
        raise SystemError('This method should not be called')

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        try:
            # Get the unverified payload
            payload = get_jwt_payload(request, verify=False)

            # Get properties
            username = payload['sub'].lower()
            email = payload['email'].lower()

            # Check if email or username missing
            if not user.username.lower() == username:
                logger.debug('User\'s username did not match JWT: {} -> {}'.format(user.username, username))
                user.username = username

            if not user.email.lower() == email:
                logger.debug('User\'s email did not match JWT: {} -> {}'.format(user.email, email))
                user.email = email

        except (KeyError, IndexError, TypeError) as e:
            logger.exception('User syncing error: {}'.format(e), exc_info=True,
                             extra={'user': user.id, 'request': request})


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
        is_active = getattr(user, 'is_active', None)
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
        try:
            # Find the user
            user = UserModel.objects.get(Q(username=username) | Q(email=email))
            logger.debug('Found user: {} : {}'.format(username, email))

            return user

        except MultipleObjectsReturned:
            logger.error('Duplicate users exist for {} : {}'.format(username, email))

        except UserModel.DoesNotExist:
            logger.debug('User does not yet exist: {} : {}'.format(username, email))

        return None

    def _create_user(self, request):
        """
        Called when a user in the model does not exist. This creates the user in the
        model.
        """
        # Check if autocreate is enabled
        if not dbmi_settings.USER_MODEL_AUTOCREATE:
            logger.debug('User autocreate is disabled, boot the current user')
            raise PermissionDenied

        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Create them
        UserModel = django_auth.get_user_model()
        user = UserModel(username=username, email=email)
        user.set_unusable_password()
        logger.debug('Created user: {}:{}'.format(username, email))

        # Sync them up
        self._sync_user(request, user)

        return user

    def _sync_user(self, request, user):
        """
        Called after a user is fetched/created and syncs any additional properties
        from the JWT's payload to the user object.
        """
        try:
            # Get the unverified payload
            payload = get_jwt_payload(request, verify=False)

            # Get properties
            username = payload['sub'].lower()
            email = payload['email'].lower()

            # Check if email or username missing
            if not user.username.lower() == username:
                logger.debug('User\'s username did not match JWT: {} -> {}'.format(user.username, username))
                user.username = username

            if not user.email.lower() == email:
                logger.debug('User\'s email did not match JWT: {} -> {}'.format(user.email, email))
                user.email = email

            # Save
            user.save()

        except (KeyError, IndexError, TypeError) as e:
            logger.exception('User syncing error: {}'.format(e), exc_info=True,
                             extra={'user': user.id, 'request': request})


class DBMIAdminModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as admin authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    Use this authentication backend for sites that are only accessible to admins and no other users.
    User model is keyed by the username and email contained in the JWT. Profile and groups are synced
    from the JWT upon each login.
    """

    @staticmethod
    def _is_admin(request):
        """
        Performs the lookups to check for admin authorizations
        """
        # Get the payload
        payload = get_jwt_payload(request, verify=False)
        email = get_jwt_email(request, verify=False)

        if not authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, dbmi_settings.AUTHZ_ADMIN_GROUP) and \
                not authz.has_permission(request, email, dbmi_settings.CLIENT, dbmi_settings.AUTHZ_ADMIN_PERMISSION):
            return False
        else:
            return True

    def _create_user(self, request):
        """
        This middleware performs exactly like its superclass, with the exception of checking
        an authenticated user's authorizations before creating them in the model. This would
        be used for sites where only admins/superusers/staff should have access.
        """
        # Before we create a user, we must ensure they have admin authorizations
        if not self._is_admin(request):
            raise PermissionDenied

        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Create them
        UserModel = django_auth.get_user_model()
        user = UserModel(username=username, email=email)
        user.set_unusable_password()
        logger.debug('Created user: {}:{}'.format(username, email))

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
        super(DBMIAdminModelAuthenticationBackend, self)._sync_user(request, user)


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
        super(DBMIAdminModelAuthenticationBackend, self)._sync_user(request, user)

        # Check if admin
        if is_admin is None:
            is_admin = self._is_admin(request)

        # Ensure the model is updated
        user.is_staff = is_admin
        user.is_superuser = is_admin
        user.save()

        # If not admin (indicates they used to be), save and raise exception
        if not is_admin:
            logger.debug('User was superuser, but is now missing authz, booting them: {}'.format(user.username))
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

    def __init__(self, request):

        # Get the payload
        payload = get_jwt_payload(request, verify=False)

        # Set properties
        self.username = payload.get('sub')
        self.id = payload.get('sub')
        self.email = payload.get('email')

    def __str__(self):
        return self.id

    def __eq__(self, other):
        return hasattr(other, 'id') and self.id == other.id

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
        return _user_get_all_permissions(self, obj)

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


# A few helper functions for common logic between User and AnonymousUser.
def _user_get_all_permissions(user, obj):
    permissions = set()

    # TODO: Query DBMI AuthZ and return all permission items 'item.permission'

    return permissions


def _user_has_perm(user, perm, obj):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    # Get all perms and compare
    try:
        for permission in _user_get_all_permissions(user, obj):
            if permission == '{}.{}'.format(obj, perm):
                return True
    except PermissionDenied:
        return False

    return False


def _user_has_module_perms(user, app_label):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    # Get all perms and compare
    try:
        for perm in _user_get_all_permissions(user, app_label):
            if '{}.{}'.format(app_label, perm) == perm:
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
        payload = validate_rs256_jwt(token)
        if not payload:
            raise exceptions.AuthenticationFailed

        # Return the user's email to attach to the request object (request.user)
        # Also, return the authz dictionary contained in the JWT claims, if present (request.auth)
        return payload.get('email'), payload.get(dbmi_settings.JWT_AUTHZ_NAMESPACE)


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
            auth = get_jwt_payload(request, verify=False).get('JWT_AUTHZ_NAMESPACE')

        # Return the user's email to attach to the request object (request.user)
        # Also, return the authz dictionary contained in the JWT claims, if present (request.auth)
        return user, auth
