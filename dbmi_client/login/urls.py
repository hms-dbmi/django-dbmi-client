from django.urls import re_path

from dbmi_client.login import views

app_name = "dbmi_login"

urlpatterns = [
    re_path(r"^auth(?:orize)?/?$", views.authorize, name="authorize"),
    re_path(r"^callback/?$", views.callback, name="callback"),
    re_path(r"^logout/?$", views.logout, name="logout"),
    re_path(r"^token/?$", views.token, name="token"),
    re_path(r"^$", views.token, name="token"),
]
