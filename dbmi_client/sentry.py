from raven.contrib.django.client import DjangoClient
from raven.contrib.django.client import get_client_ip

from dbmi_client.authn import get_jwt_username, get_jwt_email, get_jwt_value


class DBMISentryClient(DjangoClient):
    """
    This client class prevents issues during authentication where
    Sentry would try to access auth state if an error was logged
    during authentication, leading to an infinite recursion issue.
    Instead of relying on the request.user object for user properties,
    we pull them straight from the JWT, if available.
    """

    def get_user_info(self, request):

        # Get info from token header
        return {
            'ip_address': get_client_ip(request.META),
            'username': get_jwt_username(request, verify=False),
            'email': get_jwt_email(request, verify=False),
            'client': get_jwt_value(request, 'aud', verify=False),
            'tenant': get_jwt_value(request, 'iss', verify=False),
        }
