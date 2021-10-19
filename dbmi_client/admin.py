from functools import update_wrapper

from django.contrib.admin import AdminSite
from django.core.exceptions import PermissionDenied
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth.models import Group, User
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from dbmi_client.authn import login_redirect
from dbmi_client.authn import logout as dbmi_logout

import logging
logger = logging.getLogger(__name__)


class DBMIAdminSite(AdminSite):

    @never_cache
    def login(self, request, extra_context=None):
        """
        Display the login form for the given HttpRequest.
        """
        # Set the path to send a logged in user
        index_path = reverse('admin:index', current_app=self.name)

        # Check permissions
        if request.method == 'GET' and self.has_permission(request):
            # Already logged-in, redirect to admin index
            return HttpResponseRedirect(index_path)

        # Redirect to login
        next_url = request.build_absolute_uri(index_path)
        return login_redirect(request, next_url=next_url)

    @never_cache
    def logout(self, request, extra_context=None):
        """
        Log out the user for the given HttpRequest.

        This should *not* assume the user is already logged in.
        """
        return dbmi_logout(request=request)

    def admin_view(self, view, cacheable=False):
        """
        Decorator to create an admin view attached to this ``AdminSite``. This
        wraps the view and provides permission checking by calling
        ``self.has_permission``.

        You'll want to use this from within ``AdminSite.get_urls()``:

            class MyAdminSite(AdminSite):

                def get_urls(self):
                    from django.urls import path

                    urls = super().get_urls()
                    urls += [
                        path('my_view/', self.admin_view(some_view))
                    ]
                    return urls

        By default, admin_views are marked non-cacheable using the
        ``never_cache`` decorator. If the view can be safely cached, set
        cacheable=True.
        """
        def inner(request, *args, **kwargs):
            if not request.user.is_authenticated:
                # Inner import to prevent django.contrib.admin (app) from
                # importing django.contrib.auth.models.User (unrelated model).
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(
                    request.get_full_path(),
                    reverse('admin:login', current_app=self.name)
                )

            if not self.has_permission(request):
                if request.path == reverse('admin:logout', current_app=self.name):
                    index_path = reverse('admin:index', current_app=self.name)
                    return HttpResponseRedirect(index_path)
                else:
                    raise PermissionDenied()
            return view(request, *args, **kwargs)
        if not cacheable:
            inner = never_cache(inner)
        # We add csrf_protect here so this function can be used as a utility
        # function for any view, without having to repeat 'csrf_protect'.
        if not getattr(view, 'csrf_exempt', False):
            inner = csrf_protect(inner)
        return update_wrapper(inner, view)


site = DBMIAdminSite()
site.register(Group, GroupAdmin)
site.register(User, UserAdmin)
