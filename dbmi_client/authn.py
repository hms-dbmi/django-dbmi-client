import jwt
from furl import furl
import json
import base64
import requests
import jwcrypto.jwk as jwk

from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import logout
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from dbmi_client.settings import dbmi_conf

import logging
logger = logging.getLogger(__name__)


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
    if request.COOKIES.get( dbmi_conf('JWT_COOKIE_NAME')):
        return request.COOKIES.get(dbmi_conf('JWT_COOKIE_NAME'))

    # Check if JWT in HTTP Authorization header
    elif request.META.get('HTTP_AUTHORIZATION') and dbmi_conf('JWT_HTTP_PREFIX') \
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
        delattr(settings, 'AUTH0_JWKS')

    try:
        # Look in settings
        if hasattr(settings, 'AUTH0_JWKS'):
            logger.debug('Using cached JWKS')

            # Parse the cached dict and return it
            return json.loads(settings.AUTH0_JWKS)

        else:

            logger.debug('Fetching remote JWKS')

            # Build the JWKs URL
            url = furl(dbmi_conf('AUTH0')['DOMAIN'])
            url.path.segments.extend(['.well-known', 'jwks.json'])

            # Make the request
            response = requests.get(url.url)
            response.raise_for_status()

            # Parse it
            jwks = response.json()

            # Cache it
            setattr(settings, 'AUTH0_JWKS', json.dumps(jwks))

            return jwks

    except KeyError as e:
        logging.exception(e)

    except json.JSONDecodeError as e:
        logging.exception(e)

    except requests.HTTPError as e:
        logging.exception(e)

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
        logger.exception(e)

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
        if auth0_client_id not in dbmi_conf('AUTH0')['CLIENT_IDS']:
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
            logger.error(str(err))
            logger.error("JWT Expired.")

        except jwt.InvalidTokenError as err:
            logger.error(str(err))
            logger.error("Invalid JWT Token.")

    return None


def logout_redirect(request):
    """
    This will log a user out and redirect them to log in again via the AuthN server.
    :param request:
    :return: The response object that takes the user to the login page. 'next' parameter set to bring them back to their intended page.
    """
    logout(request)

    # Build the URL
    login_url = furl(dbmi_conf('AUTHN_URL'))
    login_url.path.segments.extend(['login', 'auth'])
    login_url.query.params.add('next', request.build_absolute_uri())

    # Check for branding
    if dbmi_conf('AUTHN_BRANDING'):

        # Encode it and pass it
        json_branding = json.dumps(dbmi_conf('AUTHN_BRANDING'))
        branding = base64.urlsafe_b64encode(json_branding.encode('utf-8')).decode('utf-8')
        login_url.query.params.add('branding', branding)

    # Set the URL and purge cookies
    response = redirect(login_url.url)
    response.delete_cookie(dbmi_conf('JWT_COOKIE_NAME'), domain=dbmi_conf('JWT_COOKIE_DOMAIN'))
    logger.debug('Redirecting to: {}'.format(login_url.url))

    return response

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
        return payload.get('email'), payload.get(dbmi_conf('JWT_AUTHZ_NAMESPACE'), None)