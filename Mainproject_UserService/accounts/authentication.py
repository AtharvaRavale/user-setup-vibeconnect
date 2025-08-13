# accounts/authentication.py
import jwt
from dataclasses import dataclass
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from UserService.db_router import set_current_tenant
from accounts.models import User as TenantUser


@dataclass
class AuthenticatedTenantUser:
    id: int
    username: str
    is_staff: bool
    is_superuser: bool
    is_client: bool
    is_active: bool
    tenant_alias: str

    # DRF/Django auth expects these:
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    # nice-to-haves used by some utilities/permissions
    def get_username(self) -> str:
        return self.username

    @property
    def pk(self) -> int:
        return self.id

    def __str__(self) -> str:
        return self.username


class JWTTenantAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith(f"{self.keyword} "):
            return None

        token = auth[len(self.keyword) + 1:].strip()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token expired")
        except jwt.PyJWTError:
            raise exceptions.AuthenticationFailed("Invalid token")

        tenant_alias = payload.get("tenant_alias")
        user_id = payload.get("user_id")
        username = payload.get("username")
        if not tenant_alias or not user_id or not username:
            raise exceptions.AuthenticationFailed("Invalid token payload")

        # Point ORM to tenant DB
        set_current_tenant(tenant_alias)

        try:
            tu = TenantUser.objects.using(tenant_alias).get(id=user_id, username=username)
            if not tu.is_active:
                raise exceptions.AuthenticationFailed("User inactive")
        except TenantUser.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")

        principal = AuthenticatedTenantUser(
            id=tu.id,
            username=tu.username,
            is_staff=tu.is_staff,
            is_superuser=tu.is_superuser,
            is_client=getattr(tu, "is_client", False),
            is_active=tu.is_active,
            tenant_alias=tenant_alias,
        )

        # Return (user, auth). You can return token here if you want it on request.auth.
        return (principal, token)
