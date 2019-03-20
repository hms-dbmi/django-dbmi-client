import jwt
from furl import furl
import json
import base64
import requests
import jwcrypto.jwk as jwk

from django.apps import apps
from django.contrib import auth as django_auth
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.core.exceptions import MultipleObjectsReturned
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from dbmi_client.settings import dbmi_settings
from dbmi_client import authz

# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)

# Set a key to cache JWKs under in the DBMI.AUTH0 settings
CACHED_JWKS_KEY = '__DBMI_CLIENT_CACHED_JWKS__'


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

    # Do needed logout functions and return the modified response
    return response


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
    if apps.is_installed('dbmi_client.login'):

        # Use local login URL
        login_url = furl(request.build_absolute_uri(reverse('dbmi_login:login')))

    else:

        # Build the URL using DBMI-AuthN
        login_url = furl(dbmi_settings.AUTHN_URL)
        login_url.path.segments.extend(['login', 'auth'])

    # If no next URL, determine where to dump them after logout
    if not next_url:
        if dbmi_settings.LOGIN_REDIRECT_URL:
            next_url = request.build_absolute_uri(dbmi_settings.LOGIN_REDIRECT_URL)

        else:
            next_url = request.build_absolute_uri()

    # Add next url
    logger.debug('Login next URL: {}'.format(next_url))
    login_url.query.params.add(dbmi_settings.LOGIN_REDIRECT_KEY, next_url)

    # Add the default client ID, if specified
    if hasattr(dbmi_settings, 'AUTH0_CLIENT_ID') and getattr(dbmi_settings, 'AUTH0_CLIENT_ID'):
        login_url.query.params.add('client_id', dbmi_settings.AUTH0_CLIENT_ID)

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

    logger.debug('Login URL: {}'.format(login_url.url))
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
    if apps.is_installed('dbmi_client.login'):

        # Build the URL to DBMI-Client's logout page
        logout_url = furl(request.build_absolute_uri(reverse('dbmi_login:logout')))

    else:

        # Build the URL to DBMI-AuthN's logout endpoint
        logout_url = furl(dbmi_settings.AUTHN_URL)
        logout_url.path.segments.extend(['login', 'logout'])

    # If no next URL, determine where to dump them after logout
    if not next_url:
        if dbmi_settings.LOGOUT_REDIRECT_URL:
            next_url = request.build_absolute_uri(dbmi_settings.LOGOUT_REDIRECT_URL)

        else:
            next_url = request.build_absolute_uri()

    logger.debug('Logout next URL: {}'.format(next_url))

    # Add next url
    logout_url.query.params.add(dbmi_settings.LOGOUT_REDIRECT_KEY, next_url)

    # Add the default client ID, if specified
    if hasattr(dbmi_settings, 'AUTH0_CLIENT_ID') and getattr(dbmi_settings, 'AUTH0_CLIENT_ID'):
        logout_url.query.params.add('client_id', dbmi_settings.AUTH0_CLIENT_ID)

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
        logout_url.query.params.add('branding', branding_param)

    logger.debug('Logout URL: {}'.format(logout_url.url))
    return logout_url.url


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
    algorithm = None

    # Ensure JWT exists
    if not jwt_string:
        return None

    # Determine which Auth0 Client ID (aud) this JWT pertains to.
    try:
        unverified_header = jwt.get_unverified_header(str(jwt_string))
        algorithm = unverified_header.get('alg', 'rs256').lower()

        # Check algorithm
        if algorithm == 'hs256':
            return validate_hs256_jwt(jwt_string)

        elif algorithm == 'rs256':
            return validate_rs256_jwt(jwt_string)

        else:
            logger.error(f'Unsupported JWT algorithm: {algorithm}')
            return None

    except Exception as e:
        logger.exception('Validate error: {}'.format(e), exc_info=True,
                         extra={'algorithm': algorithm})

    return None


def get_public_keys_from_auth0(tenant, refresh=False):
    '''
    Retrieves the public key from Auth0 to verify JWTs. Will
    cache the JSON response from Auth0 in Django settings
    until instructed to refresh the JWKS.
    :param tenant: The Auth0 tenant to fetch JWKs for
    :param refresh: Purges cached JWK and fetches from remote
    :return: dict
    '''

    # If refresh, delete cached key
    if refresh:
        logger.debug('Refresh requested, deleting cached JWKs')
        delattr(dbmi_settings, f'{CACHED_JWKS_KEY}{tenant}')

    try:
        # Look in settings
        if hasattr(dbmi_settings, f'{CACHED_JWKS_KEY}{tenant}'):

            # Parse the cached dict and return it
            return json.loads(getattr(dbmi_settings, f'{CACHED_JWKS_KEY}{tenant}'))

        else:

            logger.debug('Fetching remote JWKS')

            # Build the JWKs URL
            url = furl().set(scheme='https', host='{}.auth0.com'.format(tenant))
            url.path.segments.extend(['.well-known', 'jwks.json'])

            # Make the request
            response = requests.get(url.url)
            response.raise_for_status()

            # Parse it
            jwks = response.json()

            # Cache it
            setattr(dbmi_settings, f'{CACHED_JWKS_KEY}{tenant}', json.dumps(jwks))

            return jwks

    except KeyError as e:
        logger.exception(f'Error getting public keys: {e}', exc_info=True, extra={'tenant': tenant})

    except json.JSONDecodeError as e:
        logger.exception(f'Error getting public keys: {e}', exc_info=True, extra={'tenant': tenant})

    except requests.HTTPError as e:
        logger.exception(f'Error getting public keys: {e}', exc_info=True, extra={'tenant': tenant})

    return None


def retrieve_public_key(tenant, jwt_string):
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
    :param tenant: The Auth0 tenant to fetch JWKs for
    :param jwt_string: The JWT token as a string
    :return: str
    '''

    try:
        # Get the JWK
        jwks = get_public_keys_from_auth0(tenant, refresh=False)
        if not jwks:
            logger.debug('Could not fetch JWKs from Auth0, just fail out now')
            return None

        # Decode the JWTs header component
        unverified_header = jwt.get_unverified_header(str(jwt_string))

        # Check the JWK for the key the JWT was signed with
        rsa_key = get_rsa_from_jwks(jwks, unverified_header['kid'])
        if not rsa_key:
            logger.debug('No matching key found in JWKS, refreshing')
            logger.debug('Unverified JWT key id: {}'.format(unverified_header['kid']))
            logger.debug('Cached JWK keys: {}'.format([jwk['kid'] for jwk in jwks['keys']]))

            # No match found, refresh the jwks
            jwks = get_public_keys_from_auth0(tenant, refresh=True)
            logger.debug('Refreshed JWK keys: {}'.format([jwk['kid'] for jwk in jwks['keys']]))

            # Try it again
            rsa_key = get_rsa_from_jwks(jwks, unverified_header['kid'])
            if not rsa_key:
                logger.warning('Invalid JWT attempt', extra={'unverified_kid': unverified_header['kid']})
                return None

        return rsa_key

    except KeyError as e:
        logger.exception('Error retrieving public keys: {}'.format(e), exc_info=True, extra={'tenant': tenant})

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
    # We need the public key and the client ID to match against
    jwk_pub_key = None
    jwt_client_id = None

    # Determine which Auth0 Client ID (aud) this JWT pertains to.
    try:
        jwt_client_id = str(jwt.decode(jwt_string, verify=False)['aud'])

        # Check if multiple clients are specified at the client level
        if hasattr(dbmi_settings, 'AUTH0_CLIENTS') and getattr(dbmi_settings, 'AUTH0_CLIENTS'):

            # Search client IDs
            tenant = dbmi_settings.AUTH0_CLIENTS.get(jwt_client_id, {}).get('tenant')
            if tenant:
                logger.debug(f'JWT Client ID matched to tenant: {tenant}')

                # Get the public key
                jwk_pub_key = retrieve_public_key(tenant, jwt_string)

            # Log if not found
            else:
                logger.info(f'JWT client {jwt_client_id} could not be matched to any clients')

        # Check for multiple clients at the tenant level
        if not jwk_pub_key and hasattr(dbmi_settings, 'AUTH0_TENANTS') and getattr(dbmi_settings, 'AUTH0_TENANTS'):

            # Try each one
            for tenant in dbmi_settings.AUTH0_TENANTS:
                try:
                    # Get the public key
                    jwk_pub_key = retrieve_public_key(tenant, jwt_string)

                    # A public key was returned, we've got a JWT from this tenant
                    if jwk_pub_key:
                        break

                except PermissionDenied:
                    pass
            else:
                logger.info(f'JWT client {jwt_client_id} could not be matched to '
                            f'any tenants: {dbmi_settings.AUTH0_TENANTS}')

        # If not already matched, try default client
        if not jwk_pub_key and jwt_client_id == dbmi_settings.AUTH0_CLIENT_ID:

            # Get the public key
            jwk_pub_key = retrieve_public_key(dbmi_settings.AUTH0_TENANT, jwt_string)

        if not jwk_pub_key:
            logger.error(f'JWT Client ID could not be matched: {jwt_client_id}')
            return None

    except Exception as e:
        logger.exception(f'Failed to get the aud from jwt payload: {e}', exc_info=True,
                         extra={'jwt_client_id': jwt_client_id, 'jwk_pub_key': jwk_pub_key})
        return None

    # Attempt to validate with each one
    if jwk_pub_key:

        # Get the JWK
        jwk_key = jwk.JWK(**jwk_pub_key)

        # Attempt to validate the JWT (Checks both expiry and signature)
        try:
            payload = jwt.decode(jwt_string,
                                 jwk_key.export_to_pem(private_key=False),
                                 algorithms=['RS256'],
                                 leeway=120,
                                 audience=jwt_client_id)

            return payload

        except jwt.ExpiredSignatureError as e:
            logger.debug("JWT Expired: {}".format(e), extra={
                'jwt_client_id': jwt_client_id, 'jwk_pub_key': jwk_pub_key
            })

        except jwt.InvalidTokenError as e:
            logger.info("Invalid JWT Token: {}".format(e), extra={
                'jwt_client_id': jwt_client_id, 'jwk_pub_key': jwk_pub_key
            })

        except Exception as e:
            logger.exception(f'Error validating JWT: {e}', exc_info=True, extra={
                'jwt_client_id': jwt_client_id, 'jwk_pub_key': jwk_pub_key
            })

    return None


def validate_hs256_jwt(jwt_string):
    '''
    Verifies the given HS256 JWT. Returns the payload
    if verified, otherwise returns None.
    :param jwt_string: JWT as a string
    :return: dict
    '''

    # Check settings for proper setup
    if not dbmi_settings.AUTH0_SECRET or not dbmi_settings.AUTH0_CLIENT_ID:
        logger.error('Cannot verify HS256 tokens without client ID and client secret')
        raise PermissionDenied

    # Determine which Auth0 Client ID (aud) this JWT pertains to.
    jwt_client_id = None
    try:
        jwt_client_id = str(jwt.decode(jwt_string, verify=False)['aud'])

        # Perform the validation
        payload = jwt.decode(jwt_string,
                             base64.b64decode(dbmi_settings.AUTH0_SECRET, '-_'),
                             algorithms=['HS256'],
                             leeway=120,
                             audience=jwt_client_id)

        return payload

    except jwt.ExpiredSignatureError as e:
        logger.debug("JWT Expired: {}".format(e), extra={
            'jwt_client_id': jwt_client_id,
        })

    except jwt.InvalidTokenError as e:
        logger.info("Invalid JWT Token: {}".format(e), extra={
            'jwt_client_id': jwt_client_id,
        })

    except Exception as e:
        logger.exception(f'Error validating JWT: {e}', exc_info=True, extra={
            'jwt_client_id': jwt_client_id,
        })

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

        except (KeyError, IndexError, TypeError) as e:
            logger.exception('User syncing error: {}'.format(e), exc_info=True,
                             extra={'user': user.id, 'request': request})


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

        # Check if admin
        is_admin = authz.is_admin(request, user.email)
        if is_admin:
            logger.debug(f'User: {user.email} has been granted admin/superuser privileges')

        # Ensure the model is updated
        user.is_staff = is_admin
        user.is_superuser = is_admin
        user.save()


class DBMIAdminModelAuthenticationBackend(DBMIModelAuthenticationBackend):

    """
    Clients must have a valid JWT in the request (either in HTTP Authorization headers or in cookies) as
    well as admin authorization, either through JWT claims or as a permission in the DBMI AuthZ service.
    Use this authentication backend for sites that are only accessible to admins and no other users.
    User model is keyed by the username and email contained in the JWT. Profile and groups are synced
    from the JWT upon each login.
    """

    def _create_user(self, request):
        """
        This middleware performs exactly like its superclass, with the exception of checking
        an authenticated user's authorizations before creating them in the model. This would
        be used for sites where only admins/superusers/staff should have access.
        """
        # Get username and email
        username = get_jwt_username(request, verify=False)
        email = get_jwt_email(request, verify=False)

        # Before we create a user, we must ensure they have admin authorizations
        if not authz.is_admin(request, email):
            raise PermissionDenied

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
        super(DBMISuperuserModelAuthenticationBackend, self)._sync_user(request, user)

        # Check if admin
        if is_admin is None:
            is_admin = authz.is_admin(request, user.email)

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
