from django.contrib.auth import get_user_model


class EmailBackend:
    def authenticate(self, request, email=None, password=None):
        User = get_user_model()
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None
