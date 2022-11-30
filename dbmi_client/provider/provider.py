class Provider(object):
    """
    The provider class encapsulates authentication provider behaviors
    and routines.
    """
    identifier = None
    domain = None
    client_id = None
    client_secret = None
    scope = None
    callback_url = None

    def __init__(self, domain, client_id, client_secret, scope, callback_url):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.callback_url = callback_url

    def set_state(self, request, state):
        """
        This method allows the provider instance to add to or modify the state
        object that is passed along with the '/authorize' request. This allows
        the service to pass parameters through login to the redirect to the
        calling service.

        :param request: The current request
        :type request: HttpRequest
        :param state: The current state object
        :type state: dict
        """
        pass

    def get_authorize_url(self, request, state):
        """
        This method returns the URL to be used for the authorize endpoint. This typically redirects users
        to the authentication provider's hosted login.

        :param request: The current request object
        :type request: HttpRequest
        :param state: An object containing state as well as anything else that needs to pass-through
        :type state: dict
        :returns: The URL to redirect users to for initial login
        :rtype: furl
        """
        raise NotImplementedError(f"This method should be implemented by subclasses")

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
        raise NotImplementedError(f"This method should be implemented by subclasses")

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
        raise NotImplementedError(f"This method should be implemented by subclasses")

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
        raise NotImplementedError(f"This method should be implemented by subclasses")

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
        raise NotImplementedError(f"This method should be implemented by subclasses")
