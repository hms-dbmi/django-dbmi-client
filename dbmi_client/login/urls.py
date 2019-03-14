from django.conf.urls import url

from dbmi_client.login import views

app_name = "dbmi_login"

urlpatterns = [
    url(r'^login/?$', views.login,  name='login'),
    url(r'^callback/?$', views.callback,  name='callback'),
    url(r'^logout/?$', views.login,  name='logout'),
    url(r'^jwt/?$', views.token,  name='jwt'),
    url(r'^$', views.token,  name='jwt'),
]


