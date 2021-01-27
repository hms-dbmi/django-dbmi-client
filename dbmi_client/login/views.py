import requests
import json
import base64
import furl
import secrets
from urllib.parse import urlencode

from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect, reverse
from django.http import QueryDict
from dbmi_client.settings import dbmi_settings
from dbmi_client.authn import validate_request, get_jwt
from django.contrib import auth as django_auth

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


def token(request):

    # Ensure we've got a JWT
    jwt = get_jwt(request)
    if not jwt:
        return redirect("dbmi_login:login")

    # Set the token
    context = {"jwt": jwt}

    return render(request, template_name="dbmi_client/login/jwt.html", context=context)


def login(request):
    """
    Landing point to force user log in.

    This URL is a catch-all to see if a user is already logged in. The next Querystring should be set to
    redirect if the user is found to be logged in, or after they log in.
    """
    logger.debug("Checking if user is logged in already.")

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

    # Build a URL with the root URI
    callback_url = furl.furl(request.build_absolute_uri(reverse("dbmi_login:callback")))

    # Build an encoded querystring to pass along to Auth0
    query = {}
    logger.debug(f"DBMISVC/AuthN: Passed parameters: {','.join(list(request.GET.keys()))}")

    # Check for authentication query elements
    if request.GET.get(DBMI_AUTH_QUERY_BRANDING_KEY):

        # Add it
        query[DBMI_AUTH_QUERY_BRANDING_KEY] = request.GET[DBMI_AUTH_QUERY_BRANDING_KEY]

    else:

        # Add default UI customizations for Auth0 universal login
        branding = {}
        if dbmi_settings.AUTHN_TITLE:
            branding["title"] = dbmi_settings.AUTHN_TITLE
        if dbmi_settings.AUTHN_ICON_URL:
            branding["icon_url"] = dbmi_settings.AUTHN_ICON_URL
        if dbmi_settings.AUTHN_COLOR:
            branding["color"] = dbmi_settings.AUTHN_COLOR
        if dbmi_settings.AUTHN_BACKGROUND:
            branding["background"] = dbmi_settings.AUTHN_BACKGROUND

        # Add it
        query[DBMI_AUTH_QUERY_BRANDING_KEY] = base64.urlsafe_b64encode(json.dumps(branding).encode('utf-8')).decode('utf-8')

    # Add redirect URL
    if request.GET.get(DBMI_AUTH_QUERY_NEXT_KEY):

        # Add it
        query[DBMI_AUTH_QUERY_NEXT_KEY] = request.GET[DBMI_AUTH_QUERY_NEXT_KEY]

    # Add Auth0 client ID
    query[DBMI_AUTH_QUERY_CLIENT_ID_KEY] = dbmi_settings.AUTH0_CLIENT_ID

    # Revert the query back to query string and encode in base64
    query = base64.urlsafe_b64encode(urlencode(query).encode('utf-8')).decode('utf-8')

    # Add it
    callback_url.query.params.add(DBMI_AUTH_CALLBACK_QUERY_KEY, query)

    # Build authorize URL
    auth0_url = dbmi_settings.AUTH0_DOMAIN if dbmi_settings.AUTH0_DOMAIN else f"{dbmi_settings.AUTH0_TENANT}.auth0.com"
    authorize_url = furl.furl(f"https://{auth0_url}/authorize")

    # Create a token for state
    state = secrets.token_urlsafe(32)

    # Add required parameters
    authorize_url.query.params.add("response_type", "code")
    authorize_url.query.params.add("client_id", dbmi_settings.AUTH0_CLIENT_ID)
    authorize_url.query.params.add("redirect_uri", callback_url.url)
    authorize_url.query.params.add("scope", dbmi_settings.AUTH0_SCOPE)
    authorize_url.query.params.add("state", state)

    # Create the response
    response = redirect(authorize_url.url)

    # Place a cookie with state
    response.set_cookie(
        DBMI_AUTH_STATE_COOKIE_NAME,
        state,
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )

    # Place a cookie with query
    response.set_cookie(
        DBMI_AUTH_QUERY_COOKIE_NAME,
        query,
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )

    # Redirect to Auth0
    return response


def callback(request):
    """
    Callback from Auth0

    This endpoint is called by auth0 with a code that lets us know the user logged
    into their Identity Provider successfully. We need to use the code to gather
    the user information from Auth0 and establish the DBMI_JWT cookie.
    """
    logger.debug("Call returned from Auth0.")

    # Fetch some of the request parameters
    auth_url = None
    try:
        # Get the original query sent to dbmi-auth
        query = QueryDict(base64.urlsafe_b64decode(
            request.GET.get(DBMI_AUTH_CALLBACK_QUERY_KEY).encode("utf-8")
        ).decode("utf-8"))

        # Get the return URL
        auth_url = furl.furl(reverse("dbmi_login:login") + "?{}".format(query.urlencode("/")))
        logger.debug(f"dbmi-auth/login: Backup auth URL: {auth_url.url}")

    except Exception as e:
        logger.error("Failed to parse query parameters: {}".format(e), exc_info=True, extra={"request": request})

        # Set an empty dict
        query = {}

    # This is a code passed back from Auth0 that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get("code")
    if not code:
        logger.error(
            "Auth0 code error: {} - {}".format(request.GET.get("error"), request.GET.get("error_description")),
            extra={
                "request": request,
                "query": query,
                "next_url": query.get("next"),
                "auth0_error": request.GET.get("error"),
                "auth0_error_description": request.GET.get("error_description"),
            },
        )

        # Cannot proceed without code
        raise SuspiciousOperation()

    json_header = {"content-type": "application/json"}

    # This is the Auth0 URL we post the code to in order to get token.
    auth0_url = dbmi_settings.AUTH0_DOMAIN if dbmi_settings.AUTH0_DOMAIN else f"{dbmi_settings.AUTH0_TENANT}.auth0.com"
    token_url = furl.furl(f"https://{auth0_url}/oauth/token")

    # Build a URL with the root URI
    callback_url = furl.furl(request.build_absolute_uri(reverse("dbmi_login:callback")))

    # Information we pass to auth0, helps identify us and our request.
    token_payload = {
        "client_id": dbmi_settings.AUTH0_CLIENT_ID,
        "client_secret": base64.b64decode(dbmi_settings.AUTH0_SECRET.encode()).decode(),
        "redirect_uri": callback_url.url,
        "code": code,
        "grant_type": "authorization_code",
    }

    # Post the code to get the token from Auth0.
    token_response = requests.post(token_url.url, data=json.dumps(token_payload), headers=json_header)
    if not token_response.ok:
        logger.error(
            "Failed to exchange token",
            extra={
                "request": request,
                "response": token_response.content,
                "status": token_response.status_code,
                "url": token_url,
            },
        )

        # Cannot proceed without token
        raise SuspiciousOperation()

    # Get tokens
    token_info = token_response.json()

    # URL we post the token to get user info.
    user_url = furl.furl(f"https://{auth0_url}/userinfo")
    user_url.query.params.add("access_token", token_info.get("access_token"))

    # Get the user info from auth0.
    user_response = requests.get(user_url.url)
    if not user_response.ok:
        logger.error(
            "Failed to get user info",
            extra={
                "request": request,
                "response": user_response.content,
                "status": user_response.status_code,
                "url": user_url,
            },
        )

        # Cannot proceed without user information
        raise SuspiciousOperation()

    # Get user info
    user_info = user_response.json()
    email = user_info.get("email")
    jwt = token_info.get("id_token")

    if not email or not jwt:
        logger.error(
            "No email/jwt returned for user info, cannot proceed",
            extra={'user_info': user_info}
        )
        raise SuspiciousOperation()

    # Redirect the user to the page they originally requested.
    if hasattr(dbmi_settings, "LOGIN_REDIRECT_KEY") and query.get(dbmi_settings.LOGIN_REDIRECT_KEY):
        redirect_url = query.get(dbmi_settings.LOGIN_REDIRECT_KEY)

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
        jwt,
        domain=dbmi_settings.JWT_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="Lax"
    )

    # Delete state and query cookie
    response.delete_cookie(DBMI_AUTH_STATE_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)
    response.delete_cookie(DBMI_AUTH_QUERY_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

    return response

def logout(request):
    """
    User logout

    This endpoint logs out the user session from the dbmi_authn Django app.
    """
    # See if they are logged in
    if validate_request(request):

        # Build the logout URL
        url = furl.furl(f"https://{dbmi_settings.AUTH0_TENANT}.auth0.com/v2/logout")

        # Add the client ID
        url.query.params.add("client_id", dbmi_settings.AUTH0_CLIENT_ID)

        # Redirect the user to the logout page
        next_url = furl.furl(request.build_absolute_uri(reverse("dbmi_login:logout")))

        # Look for next url
        if request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY):

            # Get the passed URL
            logger.debug('Will log user out and redirect to: {}'.format(
                request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY)
            ))
            next_url.query.params.add(
                dbmi_settings.LOGOUT_REDIRECT_KEY,
                request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY)
            )

        # Redirect the user to the landing page
        url.query.params.set("returnTo", next_url)

        # Log the URL
        logger.debug(f"Logout URL: {url.url}")

        # Ensure the request is cleared of user state
        django_auth.logout(request)

        # Create the response
        response = redirect(url.url)

        # Set the URL and purge cookies
        response.delete_cookie(dbmi_settings.JWT_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

        return response

    else:
        logger.debug("User has been logged out, sending to logout page")

        # Look for next url
        if request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY):

            # Get the passed URL
            next_url = request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY)

            # Send them off
            logger.debug('Will redirect logged out user to: {}'.format(next_url))
            return redirect(next_url)

        # Render the logout landing page
        return render(request, "dbmi_client/login/logout.html")
