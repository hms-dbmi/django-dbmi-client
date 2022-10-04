import mock
import re
import unittest
import responses

from django.http import HttpResponse
from django.contrib.auth.models import User, AnonymousUser
from django.test.client import RequestFactory
from dbmi_client import authz
from dbmi_client.settings import dbmi_settings
from dbmi_client import auth


class TestAuth(unittest.TestCase):

    # User JWT
    fake_jwt = "somefakejwtalsdijlaiwjdlijawlidjasdhgashgd"

    @classmethod
    def setUpClass(cls):

        # Patch JWT checker
        cls.jwt_patcher = mock.patch("dbmi_client.authn.validate_request")
        cls.mock_jwt = cls.jwt_patcher.start()
        cls.mock_jwt.return_value = True

        # Set a user and request factory
        cls.rf = RequestFactory()
        cls.user = User.objects.create_user(
            username="test_auth_user", email="testauthuser@dbmiauth.local", password="top_secret"
        )

        # Set the authorization server URL
        cls.authz_url_pattern = re.compile(dbmi_settings.AUTHZ_URL + r".*")

    @classmethod
    def tearDownClass(cls):

        # Disable patcher
        cls.jwt_patcher.stop()

    def build_request(self, path, method="get", user=True):

        # Build the request
        request = getattr(self.rf, method)(path, HTTP_AUTHORIZATION=TestAuth.fake_jwt)

        # Set empty session
        setattr(request, "session", {})

        # Check for a user
        if user:
            # Add the user
            request.user = self.user
            request.COOKIES[dbmi_settings.JWT_COOKIE_NAME] = "JWT {}".format(TestAuth.fake_jwt)

        else:
            request.user = AnonymousUser()

        return request

    def setUp(self):

        # Setup each test
        pass

    @responses.activate
    @mock.patch("dbmi_client.authz.has_a_permission")
    def test_auth_mock_(self, mock_has_a_permission):

        # Set the response
        mock_has_a_permission.return_value = True

        # Build the request
        request = self.build_request("/some/page/")

        # Run it
        has_authz = authz.has_a_permission(request, self.user.email, "item", ["admin", "read"], check_parents=True)

        # Check it
        self.assertTrue(has_authz)

    @responses.activate
    def test_auth_response_(self):

        # Build the request
        request = self.build_request("/some/page/")

        # Build the response handler
        responses.add(responses.GET, self.authz_url_pattern, json={"error": "not found"}, status=404)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, "item", "admin", check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_auth_dbmi_user_auth(self):

        # Build the request
        request = self.build_request("/some/page/", user=True)

        # Create a fake view
        view = mock.MagicMock(return_value=HttpResponse("Some page content"))

        # Run.
        decorated = auth.dbmi_user(view)
        response = decorated(request, *[], **{})

        # Check.
        # View was called.
        view.assert_called_once_with(request, *[], **{})

        # Ensure the user is allowed
        self.assertEqual(response.status_code, 200)

    @responses.activate
    @mock.patch("dbmi_client.authn.login_redirect")
    def test_auth_dbmi_user_no_auth(self, mock_login_redirect):

        # Build the request
        request = self.build_request("/some/page/", user=False)

        # Create a fake view
        view = mock.MagicMock(return_value=HttpResponse("Some page content"))

        # Run.
        decorated = auth.dbmi_user(view)
        decorated(request, *[], **{})

        # Check.
        # View was never reached.
        view.assert_not_called()

        # Ensure the user is redirected to login.
        mock_login_redirect.assert_called_once_with(request)
