from django.contrib import auth as django_auth

from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = django_auth.get_user_model()
        exclude = [
            "password",
        ]
