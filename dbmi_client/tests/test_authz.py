import mock
import re
import unittest
import responses
from django.contrib.auth.models import User
from django.test.client import RequestFactory
from dbmi_client import authz
from dbmi_client.settings import dbmi_settings


class TestAuthz(unittest.TestCase):

    # User JWT
    fake_jwt = 'somefakejwtalsdijlaiwjdlijawlidjasdhgashgd'

    @classmethod
    def setUpClass(cls):

        # Patch JWT checker
        cls.jwt_patcher = mock.patch('dbmi_client.authn.validate_rs256_jwt')
        cls.mock_jwt = cls.jwt_patcher.start()
        cls.mock_jwt.return_value = True

        # Set a user and request factory
        cls.rf = RequestFactory()
        cls.user = User.objects.create_user(username='testuser', email='testuser@dbmiauth.local', password='top_secret')

        # Set the authorization server URL
        cls.authz_url_pattern = re.compile(dbmi_settings.AUTHZ_URL + r'.*')

    @classmethod
    def tearDownClass(cls):

        # Disable patcher
        cls.jwt_patcher.stop()

    def build_request(self, path, method='get'):

        # Build the request
        request = getattr(self.rf, method)(path, HTTP_AUTHORIZATION=TestAuthz.fake_jwt)

        # Add the user
        request.user = self.user
        request.COOKIES[dbmi_settings.JWT_COOKIE_NAME] = 'JWT {}'.format(TestAuthz.fake_jwt)

        return request

    def setUp(self):

        # Setup each test
        pass

    @responses.activate
    @mock.patch('dbmi_client.authz.has_a_permission')
    def test_authz_mock_(self, mock_has_a_permission):

        # Set the response
        mock_has_a_permission.return_value = True

        # Build the request
        request = self.build_request('/some/page/')

        # Run it
        has_authz = authz.has_a_permission(request, self.user.email, 'item', ['admin', 'read'], check_parents=True)

        # Check it
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_no_response(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'error': 'not found'},
                      status=404)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'item', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_no_perm(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'someitem', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'item', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_wrong_perm(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'item', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'item', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_case_insensitive_perm(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'item', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'ITEM', 'ADMIN', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_case_insensitive_perm_1(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'ITEM', 'permission': 'ADmIN', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'item', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_has_perm(self):

        # Build the request
        request = self.build_request('/some/page/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'item', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'item', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_parent_has_perm(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'parent.child', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_grandparent_has_perm(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'parent.child.grandchild', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_parent_wrong_perm(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'parent.child', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_child_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent.child', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'parent', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_grandchild_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent.child.grandchild', 'permission': 'admin', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_permission(request, self.user.email, 'parent.child', 'admin', check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_multiple_no_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent1', 'permission': 'admin', 'email': self.user.email},
                          {'item': 'parent2', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_a_permission(request=request,
                                           email=self.user.email,
                                           item='parent',
                                           permissions=['admin', 'read'],
                                           check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

    @responses.activate
    def test_authz_multiple_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent1', 'permission': 'admin', 'email': self.user.email},
                          {'item': 'parent', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_a_permission(request=request,
                                           email=self.user.email,
                                           item='parent',
                                           permissions=['admin', 'read'],
                                           check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_multiple_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent1', 'permission': 'admin', 'email': self.user.email},
                          {'item': 'parent', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_a_permission(request=request,
                                           email=self.user.email,
                                           item='parent',
                                           permissions=['admin', 'read'],
                                           check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_grandchild_multiple_perms(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent.child.grandchild', 'permission': 'admin', 'email': self.user.email},
                          {'item': 'parent.child', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_a_permission(request=request,
                                           email=self.user.email,
                                           item='parent.child',
                                           permissions=['admin', 'read'],
                                           check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertTrue(has_authz)

    @responses.activate
    def test_authz_grandchild_multiple_perms_1(self):

        # Build the request
        request = self.build_request('/')

        # Build the response handler
        responses.add(responses.GET,
                      self.authz_url_pattern,
                      json={'results': [
                          {'item': 'parent.child.grandchild', 'permission': 'admin', 'email': self.user.email},
                          {'item': 'parent.child', 'permission': 'read', 'email': self.user.email}
                      ]},
                      status=200)

        # Build the call
        has_authz = authz.has_a_permission(request=request,
                                           email=self.user.email,
                                           item='parent.child',
                                           permissions=['admin', 'write'],
                                           check_parents=True)

        # Check it
        self.assertGreaterEqual(len(responses.calls), 1)
        self.assertFalse(has_authz)

