from django.contrib.auth import get_user_model, backends

from web3auth.settings import app_settings
from web3auth.utils import recover_to_addr


class Web3Backend(backends.ModelBackend):
    def authenticate(self, request, address=None, token=None, signature=None):
        User = get_user_model()
        if not address == recover_to_addr(token, signature):
            return None
        else:
            address_field = app_settings.WEB3AUTH_USER_ADDRESS_FIELD
            kwargs = {
                f"{address_field}__iexact": address
            }
            # try to get user with provided data
            user = User.objects.filter(**kwargs).first()
            return user
