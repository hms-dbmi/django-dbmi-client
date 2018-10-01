============
DBMI Client
============

DBMI Client is an app to provide common functionality needed to integrate a client application
with DBMI services. DBMI services offer features like centralized authentication, custom authorizations, user
management, and more. Installing this app provides view decorators and API authentication/authorization
classes to easily utilize the DBMI services for your Django application.

Quick start
-----------

1. Install django-dbmi-client (not available yet)
::

    pip install django-dbmi-client==0.1.0

2. Add "dbmi_client" to your INSTALLED_APPS setting like this
::

    INSTALLED_APPS = [
        ...
        'dbmi_client',
    ]

3a. Configure settings for your application (dev or prod)
::

    # Example 'prod' or 'dev' configuration
    DBMI_CLIENT_CONFIG = {

        'CLIENT': 'my-client', # This string is used to identify your app in DBMI services
        'ENVIRONMENT': 'prod|dev', # The environment setting determines the URLs of DBMI services to use

        'AUTHZ_ADMIN_GROUP': 'my-client-admin', # This optional setting will give admin permissions to users with this group
        'AUTHZ_ADMIN_PERMISSION: 'admin', # This optional setting will grant a user staff/superuser status if this permissions exists for them

        'JWT_COOKIE_DOMAIN': '.my-client.hms.harvard.edu', # This setting must be a subdomain of your app's public domain

        'AUTH0_CLIENT_ID': 'xxxxxxxxxxxxxxx', # An Auth0 client to authenticate for
        'AUTH0_TENANT': 'my-client, # The Auth0 tenant identifier that your Auth0 client is registered in

        'AUTHN_TITLE': 'My Client', # A title of your app to be shown on the login screen
        'AUTHN_ICON_URL': 'https://authentication.hms.harvard.edu/static/hms_shield.png', # A square image to be shown on the login screen

        'DRF_OBJECT_OWNER_KEY': 'user' # If using DBMI Client DRF permissions, specify the lookup attribute by which object ownership should be referenced
    }

3b. If running a local or test environment, configurations might look as follows
::

    # Example local, testing, etc configuration
    # You must supply the URLs of the three services. This library will throw an exception if those are not defined.
    # To enable JWT claims inspection for groups/roles/permissions, you must also define the JWT claims namespace
    # AUTHN_URL renders the login page so this must be resolvable by the client's browser, e.g. 'localhost:8001' if running in Docker (ensure the port is exposed)
    # AUTHZ_URL and REG_URL are API only so in a Docker environment, for example, you would use their container name or defined domain name
    DBMI_CLIENT_CONFIG = {
        'CLIENT': 'my-client', # This string is used to identify your app in DBMI services
        'ENVIRONMENT': 'local', # The environment setting determines the URLs of DBMI services to use

        'AUTHN_URL': 'http://localhost:8001', # Must be resolvable by client browser
        'AUTHZ_URL': 'http://dbmiauthz:8002', # Must be resolvable from other services
        'REG_URL': 'http://dbmireg:8005', # Must be resolvable from other services

        'JWT_AUTHZ_NAMESPACE': 'http://local.authorization.dbmi.hms.harvard.edu', The namespace for JWT claims authorizations

        'AUTHZ_ADMIN_GROUP': 'my-client-admin', # This optional setting will give admin permissions to users with this group
        'AUTHZ_ADMIN_PERMISSION: 'admin', # This optional setting will grant a user staff/superuser status if this permissions exists for them

        'JWT_COOKIE_DOMAIN': '.my-client.hms.harvard.edu', # This setting must be a subdomain of your app's public domain

        'AUTH0_CLIENT_ID': 'yyyyyyyyyyyyyyyy', # An Auth0 client to authenticate for
        'AUTH0_TENANT': 'my-client, # The Auth0 tenant identifier that your Auth0 client is registered in

        'AUTHN_TITLE': 'My Client', # A title of your app to be shown on the login screen
        'AUTHN_ICON_URL': 'https://authentication.hms.harvard.edu/static/hms_shield.png', # A square image to be shown on the login screen

        'DRF_OBJECT_OWNER_KEY': 'user' # If using DBMI Client DRF permissions, specify the lookup attribute by which object ownership should be referenced
    }

4. If your site requires the User model for authenticated users, be sure to add the DBMI model backend
::

    AUTHENTICATION_BACKENDS = ['dbmi_client.authn.DBMIModelAuthenticationBackend', ... ]

Usage
------

View Authentication/Authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a user visits your site, a decorated view will automatically send them to the login service if they have not yet authenticated. To limit a Django view to authenticated users:
::

    from dbmi_client.auth import dbmi_user
    from dbmi_client.authn import get_jwt_email

    @dbmi_user
    def secure_view(self, request, *args, **kwargs):

        # The current user's email can be retrieved
        email = get_jwt_email(request)

        ...

If an authenticated user visits an admin-only view without the proper permissions, a Django PermissionDenied exception is raised. To limit a Django view to admins only
::

    from dbmi_client.auth import dbmi_user
    from dbmi_client.authn import get_jwt_email

    @dbmi_admin
    def ultra_secure_view(self, request, *args, **kwargs):

        # The current admin user's email can be retrieved
        admin_email = get_jwt_email(request)

        ...

To limit a view to users with your a custom app permission
::

    from dbmi_client.auth import dbmi_permission
    from dbmi_client.authn import get_jwt_email

    @dbmi_permission('my_permission')
    def secure_view(self, request, *args, **kwargs):

        # The current user's email can be retrieved
        email = get_jwt_email(request)

        ...

To limit a view to users with a permission on a custom item or subitem
::

    from dbmi_client.auth import dbmi_item_permission
    from dbmi_client.authn import get_jwt_email

    @dbmi_item_permission('profile.image', 'my_item_permission')
    def secure_item_view(self, request, *args, **kwargs):

        # The current user's email can be retrieved
        email = get_jwt_email(request)

        ...

API Authentication/Authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If your application utilizes the Django Rest Framework library for API management, consider the
following authentication and permission classes for controlling access.

To protect an Django-rest-framework API, you can use the built-in authentication and permission classes (this example allows users whose email is present in the object being queried or admins and users with MANAGE permission)
::

    from rest_framework import viewsets
    from dbmi_client.authn import DBMIUser
    from dbmi_client.authz import DBMIOwnerPermission, DBMIManageOrOwnerPermission

    class MyAPIViewSet(viewsets.ModelViewSet):
        """
        API View for UserPermission Model.
        """
        authentication_classes = (DBMIUser, )
        permission_classes = (DBMIOwnerPermission, DBMIManageOrOwnerPermission )

        def list(self, request, *args, **kwargs):

            # Get user email
            email = request.user

            ...

Or, a restricted API where the user model is enabled for authenticated users
::

    from rest_framework import viewsets
    from dbmi_client.authn import DBMIModelUser
    from dbmi_client.authz import DBMIOwnerPermission, DBMIManageOrOwnerPermission

    class MyAPIViewSet(viewsets.ModelViewSet):
        """
        API View for UserPermission Model.
        """
        authentication_classes = (DBMIModelUser, )
        permission_classes = (DBMIOwnerPermission, DBMIManageOrOwnerPermission )

        def list(self, request, *args, **kwargs):

            # Get user instance
            user = request.user

            # Get their email
            email = user.email

            ...

Managing Permissions
~~~~~~~~~~~~~~~~~~~~~

TBD