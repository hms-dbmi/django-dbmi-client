import base64
from furl import furl
import requests

from dbmi_client.authn import get_jwt_payload
from dbmi_client.provider.provider import Provider

import logging
logger = logging.getLogger(__name__)


class Cognito(Provider):
    """
    The provider class encapsulates authentication provider behaviors
    and routines.
    """
    identifier = "cognito"

    def get_authorize_url(self, request, state):
        """
        This method returns the URL to be used for the authorize endpoint. This typically redirects users
        to the authentication provider's hosted login.

        :param request: The current request object
        :type request: HttpRequest
        :param state: The string to use as the state parameter
        :type state: str
        :returns: The URL to redirect users to for initial login
        :rtype: str
        """
        url = furl(
            f"https://{self.domain}/oauth2/authorize"
        )

        # Add required parameters
        url.query.params.add("response_type", "code")
        url.query.params.add("client_id", self.client_id)
        url.query.params.add("redirect_uri", self.callback_url)
        url.query.params.add("scope", self.scope)
        url.query.params.add("state", state)

        return url.url

    def get_tokens(self, request, code):
        """
        This method takes an authorization code and fetches the ID and access tokens from the authentication provider.

        :param request: The current request object
        :type request: HttpRequest
        :param code: The code returned upon user's login
        :type code: str
        :returns: A tuple containing the ID token and the access token
        :rtype: str, str
        """
        # This is the URL we post the code to in order to get token.
        url = furl(f'https://{self.domain}/oauth2/token')

        # Set credentials
        credentials = base64.urlsafe_b64encode(f"{self.client_id}:{self.client_secret}".encode('utf-8')).decode('utf-8')

        # Set request headers
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            "Host": self.domain,
            "Authorization": f"Basic {credentials}",
        }

        # Information we pass to identify us and our request.
        payload = {
            'client_id': self.client_id,
            'redirect_uri': self.callback_url,
            'code': code,
            'grant_type': 'authorization_code'
        }

        # Make the request
        response = requests.post(url.url, data=payload, headers=headers)

        # Check response
        if not response.ok:
            logger.debug(
                f"Token exchange request failure: {url} / {response.status_code} / {response.content}"
            )
            logger.error(
                'Auth failure: Failed to exchange token',
                extra={
                    'url': url.url,
                    'response': response.content,
                    'status': response.status_code,
                }
            )

            # Cannot proceed without token
            return None, None

        # Return tokens
        return response.json()["id_token"], response.json()["access_token"]

    def get_user_email(self, request, access_token):
        """
        This method calls the authentication provider to return the currently logged in user's email address

        :param request: The current request object
        :type request: HttpRequest
        :param access_token: The user's access token
        :type access_token: str
        :returns: The user's email address
        :rtype: str
        """
        # Set the user profile endpoint URL
        url = furl(f'https://{self.domain}/oauth2/userInfo')

        # Set query parameters
        headers = {"Authorization": f"Bearer {access_token}"}

        # Make the request
        response = requests.get(url.url, headers=headers)

        # Check response
        if not response.ok:
            logger.debug(
                f"Profile request failure: {url} / {response.status_code} / {response.content}"
            )
            logger.error(
                'Auth failure: Failed to retrieve user profile',
                extra={
                    'url': url.url,
                    'response': response.content,
                    'status': response.status_code,
                }
            )
            return None

        # Parse email from response
        return response.json()["email"]

    def get_logout_url(self, request, next_url):
        """
        This method builds and returns the URL to redirect users to when processing a logout from the authentication
        provider. The next_url parameter allows specifying where the user will be redirected upon logout.

        :param request: The current request object
        :type request: HttpRequest
        :param next_url: The URL to redirect recently logged out users to
        :type next_url: str
        :returns: The logout URL to send users to
        :rtype: str
        """
        # Set the logout URL
        url = furl(f'https://{self.domain}/logout')

        # Add the client ID and redirect
        url.query.params.add('client_id', self.client_id)
        url.query.params.set('logout_uri', next_url)

        return url.url

    def is_member_of_group(self, request, group):
        """
        This method inspects the claims of the current request's JWT and returns
        whether the authentication provider has indicated membership in the
        passed group or not.

        :param request: The current request object
        :type request: HttpRequest
        :param group: The name of the group to check membership of
        :type group: str
        :returns: Whether the user belongs to the group or not
        :rtype: bool
        """
        # Get payload
        payload = get_jwt_payload(request)

        # Check claims for the groups list
        groups = payload.get("cognito:groups")

        # Return membership
        return groups and groups.get(group, False)
