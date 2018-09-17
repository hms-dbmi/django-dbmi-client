============
DBMI Client
============

DBMI Client is an app to provide common functionality needed to integrate a client application
with DBMI services. DBMI services offer features like centralized authentication, custom authorizations, user
management, and more. Installing this app provides view decorators and API authentication/authorization
classes to easily utilize the DBMI services for your Django application.

Quick start
-----------

1. Add "dbmi_client" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'dbmi_client',
    ]

2. Configure settings for your application::

    DBMI_CLIENT_CONFIG = {
        'CLIENT': 'my-client', # This string is used to identify your app in DBMI services
        'ENVIRONMENT': 'prod|dev|local', # The environment setting determines the URLs of DBMI services to use
        'AUTHZ_ADMIN_GROUP': 'my-client-admin', # This optional setting will give admin permissions to users with this group
        'JWT_COOKIE_DOMAIN': '.my-client.hms.harvard.edu', # This setting must be a subdomain of your app's public domain
        'AUTH0': {
            'CLIENT_IDS': 'xxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyy', # A comma-separated list of Auth0 clients to authenticate for
            'DOMAIN': 'my-client.auth0.com, # The Auth0 domain that your Auth0 client is hosted in
        },
        'AUTHN_BRANDING': {
            'TITLE': 'My Client', # A title of your app to be shown on the login screen
            'ICON_URL': 'https://authentication.hms.harvard.edu/static/hms_shield.png', # A square image to be shown on the login screen
        },
    }


3. When a user visits your site, a decorated view will automatically send them to the login service if they have not yet authenticated. To limit a Django view to authenticated users::

    from dbmi_client.auth import dbmi_user
    from dbmi_client.authn import get_jwt_email

    @dbmi_user
    def secure_view(self, request, *args, **kwargs):

        # The current user's email can be retrieved
        email = get_jwt_email(request)

        ...

4. If an authenticated user visits an admin-only view without the proper permissions, a Django PermissionDenied exception is raised. To limit a Django view to admins only::

    from dbmi_client.auth import dbmi_user
    from dbmi_client.authn import get_jwt_email

    @dbmi_admin
    def ultra_secure_view(self, request, *args, **kwargs):

        # The current admin user's email can be retrieved
        admin_email = get_jwt_email(request)

        ...

5. If your app requires custom permissions, create your permission::

    TBD

6. To limit a view to users with your custom permission::

    from dbmi_client.auth import dbmi_permission
    from dbmi_client.authn import get_jwt_email

    @dbmi_permission('my_permission')
    def secure_view(self, request, *args, **kwargs):

        # The current user's email can be retrieved
        email = get_jwt_email(request)

        ...

7. To protect an Django-rest-framework API, you can use the built-in authentication and permission classes (this example allows users whose email is present in the object being queried or admins and users with MANAGE permission)::

    from rest_framework import viewsets
    from dbmi_client.authz import DBMIOwnerPermission, DBMIManageOrOwnerPermission
    from dbmi_client.authn import DBMIUser

    class MyAPIViewSet(viewsets.ModelViewSet):
        """
        API View for UserPermission Model.
        """
        authentication_classes = (DBMIUser, )
        permission_classes = (DBMIOwnerPermission, DBMIManageOrOwnerPermission )