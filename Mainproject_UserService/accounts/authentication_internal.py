# accounts/authentication_internal.py
import os
from dataclasses import dataclass
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

@dataclass
class InternalPrincipal:
    # so DRF sees this as an authenticated principal
    is_authenticated: bool = True
    is_internal: bool = True

class InternalTokenAuthentication(BaseAuthentication):
    """
    Accept either:
      - X-Internal-Token: <token>
      - Authorization: Internal <token>
    Matches against settings.INTERNAL_REGISTER_DB_TOKEN (or env).
    """

    def authenticate(self, request):
        configured = getattr(settings, "INTERNAL_REGISTER_DB_TOKEN", None) or os.environ.get("INTERNAL_REGISTER_DB_TOKEN")
        if not configured:
            raise exceptions.AuthenticationFailed("Internal token not configured")

        token = request.headers.get("X-Internal-Token")
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Internal "):
                token = auth[len("Internal "):].strip()

        if not token:
            raise exceptions.AuthenticationFailed("Missing internal token")

        if token != configured:
            raise exceptions.AuthenticationFailed("Invalid internal token")

        # Return an authenticated placeholder user/principal
        return (InternalPrincipal(), None)
