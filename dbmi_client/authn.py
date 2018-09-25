import jwt
from furl import furl
import json
import base64
import requests
import jwcrypto.jwk as jwk

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.core.exceptions import MultipleObjectsReturned
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.contrib.auth import authenticate as django_authenticate
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from dbmi_client.settings import dbmi_conf
from dbmi_client import authz

from dbmi_client.settings import get_logger
logger = get_logger()

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
    login_url = furl(dbmi_conf('AUTHN_URL'))
    login_url.path.segments.extend(['login', 'auth'])

    # Check for the next URL
    if next_url:
        login_url.query.params.add('next', next_url)

    else:
        login_url.query.params.add('next', request.build_absolute_uri())

    # Check for branding
    if dbmi_conf('AUTHN_TITLE') or dbmi_conf('AUTHN_ICON_URL'):

        # Add the included parameters
        branding = {}
        if dbmi_conf('AUTHN_TITLE'):
            branding['title'] = dbmi_conf('AUTHN_TITLE')

        if dbmi_conf('AUTHN_TITLE'):
            branding['icon_url'] = dbmi_conf('AUTHN_ICON_URL')

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
    logout(request)

    # Get a login response
    response = redirect(login_redirect_url(request))

    # Set the URL and purge cookies
    response.delete_cookie(dbmi_conf('JWT_COOKIE_NAME'), domain=dbmi_conf('JWT_COOKIE_DOMAIN'))

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
    headers = {'Authorization': '{}{}'.format(dbmi_conf('JWT_HTTP_PREFIX'), token), 'Content-Type': content_type}

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
    if hasattr(request, 'COOKIES') and request.COOKIES.get(dbmi_conf('JWT_COOKIE_NAME')):
        return request.COOKIES.get(dbmi_conf('JWT_COOKIE_NAME'))

    # Check if JWT in HTTP Authorization header
    elif hasattr(request, 'META') and request.META.get('HTTP_AUTHORIZATION') and dbmi_conf('JWT_HTTP_PREFIX') \
            in request.META.get('HTTP_AUTHORIZATION'):

        # Remove prefix and return the token
        return request.META.get('HTTP_AUTHORIZATION').replace(dbmi_conf('JWT_HTTP_PREFIX'), '')

    return None


def get_jwt_payload(request, verify=True):

    # Get the JWT token depending on request type
    token = get_jwt(request)

    # Get the payload email
    if not verify:
        return jwt.decode(token, verify=False)

    else:
        return validate_rs256_jwt(token)


def get_jwt_email(request, verify=True):

    # Get the payload from above
    return get_jwt_payload(request, verify).get('email')


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
        delattr(settings, CACHED_JWKS_KEY)

    try:
        # Look in settings
        if hasattr(settings, CACHED_JWKS_KEY):
            logger.debug('Using cached JWKS')

            # Parse the cached dict and return it
            return json.loads(getattr(settings, CACHED_JWKS_KEY))

        else:

            logger.debug('Fetching remote JWKS')

            # Build the JWKs URL
            url = furl().set(scheme='https', host='{}.auth0.com'.format(dbmi_conf('AUTH0_TENANT')))
            url.path.segments.extend(['.well-known', 'jwks.json'])

            # Make the request
            response = requests.get(url.url)
            response.raise_for_status()

            # Parse it
            jwks = response.json()

            # Cache it
            setattr(settings, CACHED_JWKS_KEY, json.dumps(jwks))

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
            logger.error('Failed to get the aud from jwt payload')
            return None

        # Check that the Client ID is in the allowed list of Auth0 Client IDs for this application
        if auth0_client_id not in dbmi_conf('AUTH0_CLIENT_IDS'):
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

        except jwt.ExpiredSignatureError as err:
            logger.warning("JWT Expired: {}".format(err))

        except jwt.InvalidTokenError as err:
            logger.warning("Invalid JWT Token: {}".format(err))

    return None

###################################################################
#
# Django Custom Authentication Backend
#
###################################################################


def login(request, user, backend='dbmi_client.authn.DBMIModelAuthenticationBackend'):
    """
    Persist a user id and a backend in the request. This way a user doesn't
    have to reauthenticate on every request. Note that data set during
    the anonymous session is retained when the user logs in.
    """
    if user is None:
        user = request.user

    # We know the backend
    if not hasattr(user, 'backend'):
        user.backend = backend

    if hasattr(request, 'user'):
        request.user = user

    # Send the signal
    user_logged_in.send(sender=user.__class__, request=request, user=user)


def logout(request):
    """
    Remove the authenticated user's ID from the request.
    """
    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = getattr(request, 'user', None)
    if not getattr(user, 'is_authenticated', True):
        user = None
    user_logged_out.send(sender=user.__class__, request=request, user=user)

    if hasattr(request, 'user'):
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()


class DBMIModelAuthenticationBackend(ModelBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies).
    If enabled, users are auto-created upon first attempted login with a valid JWT. The
    User model is keyed by the username and email contained in the JWT. Profile and groups are synced
    from the JWT upon each login.
    """

    def authenticate(self, request, **credentials):

        # Get the token
        token = credentials.get('token')
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

        # Fetch the current User model
        User = get_user_model()
        user = None
        try:
            # Find the user
            user = User.objects.get(Q(username=username) | Q(email=email))
            logger.debug('Found user: {}:{}'.format(username, email))

        except MultipleObjectsReturned:
            logger.error('Duplicate users exist for {} : {}'.format(username, email))

        except User.DoesNotExist:

            # Check if we should autocreate users
            if dbmi_conf('USER_MODEL_AUTOCREATE'):

                # Create them
                user = User(username=username, email=email)
                user.set_unusable_password()
                logger.debug('Created user: {}:{}'.format(username, email))

        # If a user was found, sync them
        if user:

            # Update them and save them
            self.update_user(request, payload, user)

            return user

        else:
            return None

    def update_user(self, request, payload, user):
        """
        Take a recently authenticated user and sync up their local user properties
        with those contained in their JWT.
        :param request: The incoming request
        :param payload: The JWT payload
        :param user: The User
        :return: None
        """

        # Get properties
        username = payload['sub']
        email = payload['email']

        # Check if email or username missing
        if not user.username is username:
            logger.debug('User\' username did not match JWT: {} -> {}'.format(user.username, username))
            user.username = username

        if not user.email is email:
            logger.debug('User\' email did not match JWT: {} -> {}'.format(user.email, email))
            user.email = email

        # Check if configured for admin groups
        admin_group = dbmi_conf('AUTHZ_ADMIN_GROUP')

        # Inspect groups/permissions and set user properties accordingly
        if (admin_group and authz.jwt_has_authz(payload, authz.JWT_AUTHZ_GROUPS, admin_group) or
                (authz.has_permission(request, email, dbmi_conf('CLIENT'), dbmi_conf('AUTHZ_ADMIN_PERMISSION')))):
            logger.debug('User {}:{} has been set as staff/superuser'.format(username, email))

            # Give them admin flags
            user.is_staff = True
            user.is_superuser = True

        # Save them
        user.save()


class DBMIAdminModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as admin authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    Use this authentication backend for sites that are only accessible to admins and no other users.
    User model is keyed by the username and email contained in the JWT. Profile and groups are synced
    from the JWT upon each login.
    """

    def authenticate(self, request, **credentials):

        # Validate request
        payload = validate_request(request)
        if not payload:
            return None

        # Check authorization
        if authz.auth_has_authz(request.auth, authz.JWT_AUTHZ_GROUPS, dbmi_conf('AUTHZ_ADMIN_GROUP')):
            return super(DBMIAdminModelAuthenticationBackend, self).authenticate(request, **credentials)

        # Check permissions
        if authz.has_permission(request, request.user, dbmi_conf('CLIENT'), dbmi_conf('AUTHZ_ADMIN_PERMISSION')):
            return super(DBMIAdminModelAuthenticationBackend, self).authenticate(request, **credentials)

        # User has a valid JWT but is not an admin
        raise PermissionDenied


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
        return payload.get('email'), payload.get(dbmi_conf('JWT_AUTHZ_NAMESPACE'))


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
        user = django_authenticate(request, token=token)
        if not user:
            raise exceptions.AuthenticationFailed

        # Check if JWT contains AuthZ
        auth = None
        if dbmi_conf('JWT_AUTHZ_NAMESPACE'):

            # User has a valid JWT from SciAuth
            auth = get_jwt_payload(request, verify=False).get('JWT_AUTHZ_NAMESPACE')

        # Return the user's email to attach to the request object (request.user)
        # Also, return the authz dictionary contained in the JWT claims, if present (request.auth)
        return user, auth
