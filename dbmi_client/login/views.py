import base64
from furl import furl
import secrets
from urllib.parse import urlencode
import pytz
from datetime import datetime
from cryptography.fernet import MultiFernet, Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import InvalidToken
from django.conf import settings
from django.utils.encoding import force_bytes

from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect, reverse
from django.http import QueryDict
from dbmi_client.settings import dbmi_settings
from dbmi_client.authn import validate_request, get_jwt, get_jwt_client_id, get_jwt_payload
from django.contrib import auth as django_auth
from dbmi_client.provider import ProviderFactory
from dbmi_client.auth import dbmi_user

# Get the logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)

# Set a name for staching state during authentication
DBMI_AUTH_STATE_COOKIE_NAME = "DBMI_AUTH_STATE"
DBMI_AUTH_QUERY_COOKIE_NAME = "DBMI_AUTH_QUERY"
DBMI_AUTH_QUERY_CLIENT_ID_KEY = "client_id"
DBMI_AUTH_QUERY_NEXT_KEY = dbmi_settings.LOGIN_REDIRECT_KEY
DBMI_AUTH_QUERY_BRANDING_KEY = "branding"
DBMI_AUTH_CALLBACK_QUERY_KEY = "query"
DBMI_AUTH_STATE_KEY = "state"
DBMI_AUTH_LOGOUT_COOKIE_NAME = "DBMI_AUTH_LOGOUT"


def derive_fernet_key(input_key):
    """
    Derive a 32-bit b64-encoded Fernet key from arbitrary input key.

    :param input_key: The key to convert to Fernet-compatible key
    :type input_key: str
    :returns: A Fernet-compatible key
    :rtype: bytes
    """
    backend = default_backend()
    info = b'dbmi-client'
    salt = b'dbmi-client-hkdf-salt'
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=backend,
    )
    return base64.urlsafe_b64encode(hkdf.derive(force_bytes(input_key)))


@dbmi_user
def token(request):
    """
    This view is merely a landing page for already logged in users. It will
    display the value of their current JWT for manually signing requests and
    let them know when it expires.

    :param request: The current HTTP request object
    :type request: HttpRequest
    """

    # Get JWT details
    payload = get_jwt_payload(request, verify=True)
    expiration_datetime = datetime.utcfromtimestamp(payload['exp']).replace(tzinfo=pytz.utc)
    expiration_et_datetime = expiration_datetime.astimezone(pytz.timezone('US/Eastern'))

    # Set their JWT
    context = {
        'title': dbmi_settings.AUTHN_TITLE,
        'jwt': get_jwt(request),
        'jwt_expiration': expiration_et_datetime.strftime("%A %B %-d, %Y at %I:%M:%S %p ET"),
    }

    return render(request, template_name="dbmi_client/login/token.html", context=context)


def authorize(request):
    """
    This is the authorize endpoint and it will verify a user is logged in and
    redirect them accordingly or proceed with the OAuth2 process to log the user
    in with the given auth provider.

    :param request: The current HTTP request object
    :type request: HttpRequest
    """
    logger.debug("Checking auth")

    # Check for an existing valid DBMI JWT
    if validate_request(request):

        # Determine where to send them
        if hasattr(dbmi_settings, "LOGIN_REDIRECT_KEY") and request.GET.get(dbmi_settings.LOGIN_REDIRECT_KEY):
            redirect_url = request.GET.get(dbmi_settings.LOGIN_REDIRECT_KEY)

        elif hasattr(dbmi_settings, "LOGIN_REDIRECT_URL"):
            redirect_url = dbmi_settings.LOGIN_REDIRECT_URL

        else:
            redirect_url = request.build_absolute_uri(reverse("dbmi_login:jwt"))

        # Log their next destination
        logger.debug(f"Logged in, forward user to: {redirect_url}")

        return redirect(redirect_url)

    # Get the client ID or the default client ID which is first in the settings
    client_id = request.GET.get(DBMI_AUTH_QUERY_CLIENT_ID_KEY, next(iter(dbmi_settings.AUTH_CLIENTS.keys())))

    # Build a URL with the root URI
    callback_url = furl(request.build_absolute_uri(reverse("dbmi_login:callback")))
    logger.debug(f"Callback URL: {callback_url.url}")

    # Intialize the authentication backend
    provider = ProviderFactory.create(client_id, callback_url.url)
    logger.debug(f"Provider '{provider.identifier}' matched to client ID '{client_id}'")

    # Build an encoded querystring to pass along as state
    state = {}
    logger.debug(f"Passed parameters: {','.join(list(request.GET.keys()))}")

    # Add redirect URL
    if request.GET.get(DBMI_AUTH_QUERY_NEXT_KEY):

        # Add it
        state[DBMI_AUTH_QUERY_NEXT_KEY] = request.GET[DBMI_AUTH_QUERY_NEXT_KEY]

    # Add client ID
    state[DBMI_AUTH_QUERY_CLIENT_ID_KEY] = client_id

    # Create a token for state
    token = secrets.token_urlsafe(32)
    state["state"] = token

    # Add additional state if necessary
    provider.set_state(request, state)

    # Build authorize URL with base64 encoded state querystring
    authorize_url = provider.get_authorize_url(
        request,
        base64.urlsafe_b64encode(urlencode(state).encode('utf-8')).decode('utf-8')
    )

    # Create the response
    response = redirect(authorize_url)

    # Encrypt the state querystring for storing in cookie
    keys = [settings.SECRET_KEY] + dbmi_settings.AUTH_ENCRYPTION_KEYS
    fernet = MultiFernet([Fernet(derive_fernet_key(k)) for k in keys])
    state_enc = fernet.encrypt(urlencode(state).encode('utf-8')).decode('utf-8')

    # Place a cookie with state
    response.set_cookie(
        DBMI_AUTH_STATE_COOKIE_NAME,
        state_enc,
        max_age=2592000,
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )

    # Redirect to auth provider
    return response


def check_state(request):
    """
    This endpoint is called upon callback from the auth provider and will
    retrieve the local state as well as the state in the query of the
    returning call to verify that they match. If they do not match, or an
    error is encountered while fetching state, the check is failed. Returns
    a tuple of check status, the state object.

    :param request: The current HTTP request object
    :type request: HttpRequest
    :returns: Whether the state matches or not, the state object
    :rtype: bool, dict
    """
    # Fetch some of the request parameters
    state = None
    try:
        # Get query from state in returning call
        return_state = QueryDict(base64.urlsafe_b64decode(request.GET["state"].encode('utf-8')).decode('utf-8'))

        # Get encrypted state in cookies
        state_enc = request.COOKIES.get(DBMI_AUTH_STATE_COOKIE_NAME)

        # Decrypt the state cookie
        keys = [settings.SECRET_KEY] + dbmi_settings.AUTH_ENCRYPTION_KEYS
        fernet = MultiFernet([Fernet(derive_fernet_key(k)) for k in keys])
        state = QueryDict(fernet.decrypt(state_enc.encode('utf-8')).decode('utf-8'), mutable=True)

        # Compare state tokens
        token = next(iter(state.pop("state")))
        if token != return_state["state"]:
            logger.error('Auth error: mismatched state',
                extra={
                    'request': request, 'state': state, 'token': token,
                    'auth_error': request.GET.get('error'),
                    'auth_error_description': request.GET.get('error_description')
                }
            )

            # Fail the check
            return False, state

        return True, state

    except InvalidToken as e:
        logger.error(f'Failed to decrypt cookie state: {e}', exc_info=True)

    except Exception as e:
        logger.error(
            f'Failed to load query(s): {e}',
            exc_info=True,
            extra={'request': request}
        )

    return False, state


def callback(request):
    """
    This endpoint is called by the auth provider with a code that lets us
    know the user logged into their Identity Provider successfully.
    We need to use the code to gather the user information from the auth
    provider and establish the DBMI_JWT cookie containing their valid JWT.

    :param request: The current HTTP request object
    :type request: HttpRequest
    """
    logger.debug("Callback")

    # Retrieve and check state
    matched, state = check_state(request)

    # Handle failure
    if not matched:
        return login_failure(
            request,
            "The authentication provider returned mismatching state. Please retry login.",
            state,
        )

    # This is a code passed back from provider that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get('code')
    if not code:
        logger.error('Auth code error: {} - {}'.format(
                request.GET.get('error'),
                request.GET.get('error_description')
            ),
            extra={
                'request': request, 'state': state,
                'auth_error': request.GET.get('error'),
                'auth_error_description': request.GET.get('error_description')
            }
        )
        return login_failure(
            request,
            request.GET.get('error_description'),
            state,
        )

    # Build a URL with the root URI
    callback_url = furl(request.build_absolute_uri(reverse("dbmi_login:callback")))

    # Get the client ID
    client_id = state.get(DBMI_AUTH_QUERY_CLIENT_ID_KEY)

    # Intialize the authentication backend
    provider = ProviderFactory.create(client_id, callback_url.url)
    logger.debug(f"Provider '{provider.identifier}' matched to client ID '{client_id}'")

    # Get the tokens
    id_token, access_token = provider.get_tokens(request, code)
    if not id_token or not access_token:
        logger.error(
            "No id or access tokens returned for user, cannot proceed",
        )
        return login_failure(
            request,
            "The user's tokens could not be fetched from the authentication provider.",
            state,
        )

    # Get email
    email = provider.get_user_email(request, access_token)
    if not email:
        logger.error(
            "No email returned for user info, cannot proceed"
        )
        return login_failure(
            request,
            "The user's email address could not be fetched from the authentication provider.",
            state,
        )

    # Redirect the user to the page they originally requested.
    if hasattr(dbmi_settings, "LOGIN_REDIRECT_KEY") and state.get(dbmi_settings.LOGIN_REDIRECT_KEY):
        redirect_url = state.get(dbmi_settings.LOGIN_REDIRECT_KEY)

    elif hasattr(dbmi_settings, "LOGIN_REDIRECT_URL"):
        redirect_url = dbmi_settings.LOGIN_REDIRECT_URL

    else:
        redirect_url = request.build_absolute_uri(reverse("dbmi_login:jwt"))

    logger.debug("Redirecting user to: {}".format(redirect_url))

    # Build response
    response = redirect(redirect_url)

    # Set the JWT into a cookie in the response.
    response.set_cookie(
        dbmi_settings.JWT_COOKIE_NAME,
        id_token,
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )

    # Delete state cookie
    response.delete_cookie(DBMI_AUTH_STATE_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

    return response


def login_failure(request, error, query=None):
    """
    This method builds and returns a response intended to inform the user
    of a login failure and provide remediation via retry.

    :param request: The current HTTP request object
    :type request: HttpRequest
    :param error: The error message to display
    :type error: str
    :param query: The original query as a QueryDict to include with subsequent login attempts
    :type query: QueryDict, defaults to None
    """
    # Get querystring
    querystring = f"?{query.urlencode('/')}" if query else ""

    # Get the backup authentication URL
    auth_url = furl(
        f"{request.build_absolute_uri(reverse('dbmi_login:authorize'))}{querystring}"
    )
    logger.debug(f"Backup auth URL: {auth_url.url}")

    # Set context for error page
    context = {
        "error_description": error,
        "retry_url": auth_url.url
    }

    # Render the error page
    return render(request, 'dbmi_client/login/error.html', context)

def logout(request):
    """
    This endpoint terminates a user's logged in session and redirects them
    accordingly. The session is both terminated via auth provider as well
    as locally by deleting the cookie containing their JWT.

    :param request: The current HTTP request object
    :type request: HttpRequest
    """
    # See if they are logged in
    if validate_request(request):

        # Redirect the user to the logout page
        next_url = furl(request.build_absolute_uri(reverse("dbmi_login:logout")))

        # Get the client ID
        client_id = get_jwt_client_id(request)

        # Intialize the authentication backend
        provider = ProviderFactory.create(client_id, None)
        logger.debug(f"Provider '{provider.identifier}' matched to client ID '{client_id}'")

        # Get the logout URL
        url = provider.get_logout_url(request, next_url.url)

        # Log the URL
        logger.debug(f"Logout URL: {url}")

        # Ensure the request is cleared of user state
        django_auth.logout(request)

        # Create the response
        response = redirect(url)

        # Look for next url
        if request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY):

            # Get the passed URL
            logger.debug('Will log user out and redirect to: {}'.format(
                request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY)
            ))

            # Set the next URL into a cookie in the response.
            response.set_cookie(
                DBMI_AUTH_LOGOUT_COOKIE_NAME,
                request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY),
                domain=dbmi_settings.JWT_COOKIE_DOMAIN,
                secure=True,
                httponly=True,
                samesite="Lax"
            )

        # Set the URL and purge cookies
        response.delete_cookie(dbmi_settings.JWT_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

        return response

    else:
        logger.debug("User has been logged out, sending to logout page")

        # Check cookies for the redirect URL
        next_url = request.COOKIES.get(DBMI_AUTH_LOGOUT_COOKIE_NAME)

        # Look for next url
        if next_url:

            # Prepare the response
            response = redirect(next_url)

            # Delete cookie with redirect URL
            response.delete_cookie(DBMI_AUTH_LOGOUT_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

            # Send them off
            logger.debug('Will redirect logged out user to: {}'.format(next_url))
            return response

        # Set context
        context = {
            "title": dbmi_settings.AUTHN_TITLE,
        }

        # Render the logout landing page
        return render(request, "dbmi_client/login/logout.html", context)
