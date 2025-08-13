# accounts/authentication_master.py
import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from config.models import Superadmin

class MasterJWTAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith(f"{self.keyword} "):
            return None

        token = auth[len(self.keyword) + 1:].strip()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.PyJWTError:
            raise exceptions.AuthenticationFailed("Invalid admin token")

        admin_id = payload.get("admin_id")
        username = payload.get("admin_username")
        is_superadmin = payload.get("is_superadmin")

        if not admin_id or not username or not is_superadmin:
            raise exceptions.AuthenticationFailed("Invalid admin token payload")

        try:
            sa = Superadmin.objects.get(id=admin_id, username=username, is_staff=True, is_active=True)
        except Superadmin.DoesNotExist:
            raise exceptions.AuthenticationFailed("Admin not found or not superadmin")

        return (sa, None)
