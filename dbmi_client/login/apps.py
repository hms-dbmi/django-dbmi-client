from django.apps import AppConfig


class DBMILoginConfig(AppConfig):
    name = "dbmi_client.login"
    verbose_name = "DBMI Client Login"

    def ready(self):
        pass
