import requests
import json
import base64
import furl

from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse, QueryDict
from dbmi_client.settings import dbmi_settings
from dbmi_client.authn import validate_request, get_jwt
from django.contrib import auth as django_auth

# Get the logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


def token(request):

    # Ensure we've got a JWT
    jwt = get_jwt(request)
    if not jwt:
        return redirect('dbmi_login:login')

    # Set the token
    context = {
        'jwt': jwt
    }

    return render(request, template_name='dbmi_client/login/jwt.html', context=context)


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
        if hasattr(dbmi_settings, 'LOGIN_REDIRECT_KEY') and request.GET.get(dbmi_settings.LOGIN_REDIRECT_KEY):
            redirect_url = request.GET.get(dbmi_settings.LOGIN_REDIRECT_KEY)

        elif hasattr(dbmi_settings, 'LOGIN_REDIRECT_URL'):
            redirect_url = dbmi_settings.LOGIN_REDIRECT_URL

        else:
            redirect_url = request.build_absolute_uri(reverse('dbmi_login:jwt'))

        # Log their next destination
        logger.debug(f'Logged in, forward user to: {redirect_url}')

        return redirect(redirect_url)

    # Build a URL with the root URI
    callback_url = furl.furl(request.build_absolute_uri(reverse('dbmi_login:callback')))

    # Pass along any parameters as base64 encoded
    query = base64.urlsafe_b64encode(request.META.get('QUERY_STRING').encode('utf-8')).decode('utf-8')
    callback_url.query.params.add('query', query)

    # Initialize the context.
    context = {
        'callback_url': callback_url.url,
        'auth0_client_id': dbmi_settings.AUTH0_CLIENT_ID,
        'auth0_domain': '{}.auth0.com'.format(dbmi_settings.AUTH0_TENANT),
        'title': dbmi_settings.AUTHN_TITLE,
        'icon_url': dbmi_settings.AUTHN_ICON_URL
    }

    return render(request, template_name='dbmi_client/login/login.html', context=context)


def callback(request):
    """
    Callback from Auth0

    This endpoint is called by auth0 with a code that lets us know the user logged into their Identity Provider successfully.
    We need to use the code to gather the user information from Auth0 and establish the DBMI_JWT cookie.
    """
    logger.debug("Call returned from Auth0.")

    # Fetch some of the request parameters
    query = None
    login_url = furl.furl(request.build_absolute_uri(reverse('dbmi_login:login')))
    try:
        # Get the original query sent to dbmiauth
        query = QueryDict(base64.urlsafe_b64decode(request.GET.get('query').encode('utf-8')).decode('utf-8'))

        # Get the return URL
        login_url = login_url.url + '?{}'.format(query.urlencode('/'))

    except Exception as e:
        logger.error('Failed to parse query parameters: {}'.format(e), exc_info=True, extra={'request': request})

    # This is a code passed back from Auth0 that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get('code')
    if not code:
        logger.error('No code from Auth0', exc_info=True, extra={'request': request})

        # Redirect back to the auth screen and attach the original query
        return redirect(login_url)

    json_header = {'content-type': 'application/json'}

    # This is the Auth0 URL we post the code to in order to get token.
    token_url = 'https://%s.auth0.com/oauth/token' % dbmi_settings.AUTH0_TENANT

    # Build a URL with the root URI
    callback_url = furl.furl(request.build_absolute_uri(reverse('dbmi_login:callback')))

    # Information we pass to auth0, helps identify us and our request.
    token_payload = {
        'client_id': dbmi_settings.AUTH0_CLIENT_ID,
        'client_secret': base64.b64decode(dbmi_settings.AUTH0_SECRET.encode()).decode(),
        'redirect_uri': callback_url.url,
        'code': code,
        'grant_type': 'authorization_code'
    }

    # Post the code to get the token from Auth0.
    token_response = requests.post(token_url, data=json.dumps(token_payload), headers=json_header)
    if not token_response.ok:
        logger.error('Failed to exchange token', exc_info=True, extra={
            'request': request, 'response': token_response.content,
            'status': token_response.status_code, 'url': token_url,
        })

        # Redirect back to the auth screen and attach the original query
        return redirect(login_url)

    # Get tokens
    token_info = token_response.json()

    # URL we post the token to get user info.
    url = 'https://%s.auth0.com/userinfo?access_token=%s'
    user_url = url % (dbmi_settings.AUTH0_TENANT, token_info.get('access_token', ''))

    # Get the user info from auth0.
    user_response = requests.get(user_url)
    if not user_response.ok:
        logger.error('Failed to get user info', exc_info=True, extra={
            'request': request, 'response': user_response.content,
            'status': user_response.status_code, 'url': user_url,
        })

        # Redirect back to the auth screen and attach the original query
        return redirect(login_url)

    # Get user info
    user_info = user_response.json()
    email = user_info.get('email')
    jwt = token_info.get('id_token')
    if email and jwt:

        # Redirect the user to the page they originally requested.
        if hasattr(dbmi_settings, 'LOGIN_REDIRECT_KEY') and query.get(dbmi_settings.LOGIN_REDIRECT_KEY):
            redirect_url = query.get(dbmi_settings.LOGIN_REDIRECT_KEY)

        elif hasattr(dbmi_settings, 'LOGIN_REDIRECT_URL'):
            redirect_url = dbmi_settings.LOGIN_REDIRECT_URL

        else:
            redirect_url = request.build_absolute_uri(reverse('dbmi_login:jwt'))

        logger.debug('Redirecting user to: {}'.format(redirect_url))

        # Set the JWT into a cookie in the response.
        response = redirect(redirect_url)
        response.set_cookie(dbmi_settings.JWT_COOKIE_NAME, jwt, domain=dbmi_settings.JWT_COOKIE_DOMAIN, httponly=True)

        return response

    else:
        logger.error("No email/jwt returned for user info, cannot proceed", exc_info=True, extra={'user_info': user_info})
        return HttpResponse(status=500)


def logout(request):
    """
    User logout

    This endpoint logs out the user session from the dbmi_authn Django app.
    """
    # See if they are logged in
    if validate_request(request):

        # Build the logout URL
        url = furl.furl(f'https://{dbmi_settings.AUTH0_TENANT}.auth0.com/v2/logout')

        # Add the client ID
        url.query.params.add('client_id', dbmi_settings.AUTH0_CLIENT_ID)

        # Look for next url
        if request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY):

            # Get the passed URL
            next_url = request.GET.get(dbmi_settings.LOGOUT_REDIRECT_KEY)
            logger.debug('Will log user out and redirect to: {}'.format(next_url))

            # Redirect the user
            url.query.params.set('returnTo', next_url)

        else:
            logger.debug('Will log user out and redirect to log out page')

            # Redirect the user to the landing page
            url.query.params.set('returnTo', request.build_absolute_uri(reverse('dbmi_login:logout')))

        # Log the URL
        logger.debug(f'Logout URL: {url.url}')

        # Ensure the request is cleared of user state
        django_auth.logout(request)

        # Create the response
        response = redirect(url.url)

        # Set the URL and purge cookies
        response.delete_cookie(dbmi_settings.JWT_COOKIE_NAME, domain=dbmi_settings.JWT_COOKIE_DOMAIN)

        return response

    else:
        logger.debug('User has been logged out, sending to logout page')

        # Render the logout landing page
        return render(request, 'dbmi_client/login/logout.html')