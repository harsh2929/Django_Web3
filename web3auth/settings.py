from django.conf import settings as django_settings


class AppSettings(object):
    @property
    def WEB3AUTH_USER_ADDRESS_FIELD(self):

        return getattr(django_settings, 'WEB3AUTH_USER_ADDRESS_FIELD', 'username')

    @property
    def WEB3AUTH_USER_SIGNUP_FIELDS(self):

        return getattr(django_settings, "WEB3AUTH_USER_SIGNUP_FIELDS", ['email'])

    @property
    def WEB3AUTH_SIGNUP_ENABLED(self):

        return getattr(django_settings, "WEB3AUTH_SIGNUP_ENABLED", True)


app_settings = AppSettings()
