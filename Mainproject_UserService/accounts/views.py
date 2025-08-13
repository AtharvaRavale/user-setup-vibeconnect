from pathlib import Path
import os
import environ
from django.db import IntegrityError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db.utils import OperationalError
from config.models import UserDatabase
import jwt
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.db import connections
from django.contrib.auth.hashers import check_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from config.models import UserDatabase
from accounts.models import User as TenantUser
from .serializers import LoginSerializer
from UserService.db_router import set_current_tenant
import os
from pathlib import Path
import environ
from django.db import IntegrityError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from config.models import UserDatabase
from .serializers import (
    AutoOnboardByUsernameSerializer,
    ManualServerOnboardSerializer,
)
from .utils import (
    onboard_client_db_by_username,
    manual_onboard_with_server,
    random_password,
)

#atharva
# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from django.db.models.functions import Lower
from django.db import transaction

from config.models import UserDatabase, MainModule
from .serializers import ProvisionTenantModulesSerializer
from .utils import onboard_client_db_by_username
import os
from pathlib import Path
import environ
from django.db import connections
from rest_framework import exceptions
from accounts.models import *

class AutoOnboardByUsernameAPIView(APIView):
    def post(self, request):
        ser = AutoOnboardByUsernameSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        data = ser.validated_data
        tenant_username = data["tenant_username"]

        # duplicate by username (ci)
        if UserDatabase.objects.filter(username__iexact=tenant_username).exists():
            return Response(
                {"code": "already_provisioned", "detail": "Username already provisioned."},
                status=status.HTTP_409_CONFLICT,
            )

        # resolve PG super pass
        pg_superpass = data.get("pg_superpass") or os.environ.get("PG_SUPER_PASS")
        if not pg_superpass:
            env = environ.Env()
            env_path = str(Path(__file__).resolve().parent.parent / ".env")
            if os.path.exists(env_path):
                environ.Env.read_env(env_path)
                pg_superpass = os.environ.get("PG_SUPER_PASS")
        if not pg_superpass:
            return Response(
                {"code": "missing_pg_super_pass", "detail": "PG_SUPER_PASS is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        initial_pw = data.get("tenant_admin_password") or random_password()

        try:
            db_entry, effective_pw = onboard_client_db_by_username(
                tenant_username=tenant_username,
                tenant_admin_password=initial_pw,
                db_host=data.get("db_host", "localhost"),
                db_port=data.get("db_port", "5432"),
                pg_superuser=data.get("pg_superuser", "postgres"),
                pg_superpass=pg_superpass,
            )
            return Response(
                {
                    "detail": "Tenant created, migrated, admin ensured.",
                    "db_info": {
                        "user_id": db_entry.user_id,
                        "username": db_entry.username,
                        "db_name": db_entry.db_name,
                        "db_user": db_entry.db_user,
                        "db_host": db_entry.db_host,
                        "db_port": db_entry.db_port,
                        "db_type": getattr(db_entry, "db_type", "self_hosted"),
                        "db_password_encrypted": db_entry.db_password,
                    },
                    "tenant_admin": {
                        "username": tenant_username,
                        "initial_password": effective_pw,
                    },
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            msg = str(e)
            if msg == "username_already_provisioned":
                return Response({"code": "already_provisioned", "detail": msg}, status=409)
            if msg.startswith("role_exists:"):
                return Response({"code": "role_exists", "detail": msg}, status=409)
            if msg.startswith("database_exists:"):
                return Response({"code": "database_exists", "detail": msg}, status=409)
            return Response({"code": "internal_error", "detail": msg}, status=500)


class ManualOnboardByUsernameAPIView(APIView):
    """
    POST /api/manual-onboard-server/
    - Only needs PG superuser creds + tenant_username (+ optional names).
    - Creates role+db, migrates, seeds admin.
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = ManualServerOnboardSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
        d = ser.validated_data

        try:
            db_entry, admin_pw, tenant_db_pw = manual_onboard_with_server(
                tenant_username=d["tenant_username"],
                pg_superuser=d.get("pg_superuser", "postgres"),
                pg_superpass=d["pg_superpass"],
                db_host=d.get("db_host", "localhost"),
                db_port=d.get("db_port", "5432"),
                db_name=d.get("db_name") or None,
                db_user=d.get("db_user") or None,
                tenant_admin_password=d.get("tenant_admin_password") or None,
            )

            return Response(
                {
                    "detail": "Tenant provisioned.",
                    "db_info": {
                        "user_id": db_entry.user_id,
                        "username": db_entry.username,
                        "db_name": db_entry.db_name,
                        "db_user": db_entry.db_user,
                        "db_password_encrypted": db_entry.db_password,
                        "db_host": db_entry.db_host,
                        "db_port": db_entry.db_port,
                    },
                    "secrets": {
                        "tenant_db_password_plain": tenant_db_pw,      # show once
                        "tenant_admin_password_plain": admin_pw,       # show once
                    }
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            msg = str(e)
            if msg.startswith("username_already_provisioned"):
                return Response(
                    {"code": "already_provisioned", "detail": "Username already provisioned."},
                    status=status.HTTP_409_CONFLICT,
                )
            if msg.startswith("role_exists:"):
                return Response(
                    {"code": "role_exists", "detail": msg},
                    status=status.HTTP_409_CONFLICT,
                )
            if msg.startswith("database_exists:"):
                return Response(
                    {"code": "database_exists", "detail": msg},
                    status=status.HTTP_409_CONFLICT,
                )
            return Response({"code": "internal_error", "detail": msg}, status=500)


def _ensure_alias_from_row(row: UserDatabase) -> str:
    alias = f"client_{row.user_id}"
    if alias not in settings.DATABASES:
        from accounts.utils import decrypt_password  
        real_pw = decrypt_password(row.db_password)

        settings.DATABASES[alias] = {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": row.db_name,
            "USER": row.db_user,
            "PASSWORD": real_pw,
            "HOST": row.db_host,
            "PORT": row.db_port,
            "OPTIONS": {
            },
            "TIME_ZONE": None,    
            "ATOMIC_REQUESTS": False,     
            "AUTOCOMMIT": True,           
            "CONN_HEALTH_CHECKS": False,  
            "CONN_MAX_AGE": 0,           
            }
        connections.databases[alias] = settings.DATABASES[alias]
    return alias

# def _issue_jwt(*, user_id: int, username: str, tenant_alias: str, minutes: int = 60) -> str:
#     now =timezone.now()
#     payload = {
#         "user_id": user_id,
#         "username": username,
#         "tenant_alias": tenant_alias,
#         "iat": int(now.timestamp()),
#         "exp": int((now + timedelta(minutes=minutes)).timestamp()),
#     }
#     return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
def _issue_jwt(*, user_id: int, username: str, tenant_alias: str, minutes: int = 60, extra: dict | None = None) -> str:
    now = timezone.now()
    payload = {
        "user_id": user_id,
        "username": username,
        "tenant_alias": tenant_alias,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def _issue_refresh_jwt(*, user_id: int, username: str, tenant_alias: str, days: int = 14, extra: dict | None = None) -> str:
    now = timezone.now()
    payload = {
        "typ": "refresh",
        "user_id": user_id,
        "username": username,
        "tenant_alias": tenant_alias,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=days)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")



# accounts/mixins.py (or keep in views.py)
from rest_framework.views import APIView
from rest_framework import exceptions
from django.conf import settings
from django.db import connections
from config.models import UserDatabase
from accounts.utils import decrypt_password
from UserService.db_router import set_current_tenant

class ClientScopedMixin(APIView):
    def _get_client_username(self, request):
        data = (getattr(request, "data", {}) or {})
        qp = request.query_params
        # accept both, prefer body
        return (
            data.get("client_username")
            or data.get("client_id")
            or qp.get("client_username")
            or qp.get("client_id")
        )

    def _ensure_alias_from_row(self, row: UserDatabase) -> str:
        alias = f"client_{row.user_id}"
        if alias not in settings.DATABASES:
            real_pw = decrypt_password(row.db_password)
            settings.DATABASES[alias] = {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": row.db_name,
                "USER": row.db_user,
                "PASSWORD": real_pw,
                "HOST": row.db_host,
                "PORT": row.db_port,
                "OPTIONS": {
        },
        "TIME_ZONE": None,    
        "ATOMIC_REQUESTS": False,     
        "AUTOCOMMIT": True,           
        "CONN_HEALTH_CHECKS": False,  
        "CONN_MAX_AGE": 0,           
            }
            connections.databases[alias] = settings.DATABASES[alias]
        return alias

    def initial(self, request, *args, **kwargs):
        client_username = self._get_client_username(request)
        if not client_username:
            raise exceptions.ValidationError({"client_username": "Provide client_username (or client_id)."})

        row = UserDatabase.objects.filter(username__iexact=client_username).first()
        if not row:
            raise exceptions.ValidationError({"client_username": "Unknown client."})

        alias = self._ensure_alias_from_row(row)
        set_current_tenant(alias)

        # normalize into request.data so serializers don’t complain
        if hasattr(request, "data") and isinstance(request.data, dict):
            request.data.setdefault("client_username", client_username)

        super().initial(request, *args, **kwargs)

# accounts/views.py (top)
from .permissions_utils import build_permissions_map


# accounts/views.py
class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = LoginSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        username_in = ser.validated_data["username"].strip()
        password_in = ser.validated_data["password"]
        client_username = (ser.validated_data.get("client_username") or "").strip()

        # 1) Pick tenant row
        if client_username:
            row = UserDatabase.objects.filter(username__iexact=client_username).first()
        else:
            # fallback: try to use the submitted username as the tenant key
            row = UserDatabase.objects.filter(username__iexact=username_in).first()

        if not row:
            return Response(
                {
                    "code": "tenant_not_found",
                    "detail": "Tenant not found. Provide client_username explicitly if your username is not the tenant key."
                },
                status=404,
            )

        # 2) Switch to tenant DB
        tenant_alias = _ensure_alias_from_row(row)
        set_current_tenant(tenant_alias)

        # 3) Find user inside tenant DB by the submitted username
        tu = (
            TenantUser.objects.using(tenant_alias)
            .filter(username__iexact=username_in)
            .first()
        )
        if not tu:
            return Response(
                {"code": "user_not_found", "detail": "Username not found in tenant DB."},
                status=404,
            )
        if not tu.is_active:
            return Response({"code": "inactive_user", "detail": "User is inactive."}, status=403)

        if not check_password(password_in, tu.password):
            return Response({"code": "invalid_credentials", "detail": "Invalid username/password."}, status=401)

        # 4) Permissions payload
        permissions_map = build_permissions_map(tu, using_alias=tenant_alias)

        # 5) Tokens
        access_token = _issue_jwt(
            user_id=tu.id,
            username=tu.username,
            tenant_alias=tenant_alias,
            minutes=60,
            extra={"type": "access", "permissions": permissions_map},
        )
        refresh_token = _issue_refresh_jwt(
            user_id=tu.id,
            username=tu.username,
            tenant_alias=tenant_alias,
            days=7,
            extra={"type": "refresh", "permissions": permissions_map},
        )

        return Response(
            {
                "detail": "Logged in.",
                "token_type": "Bearer",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "permissions": permissions_map,
                "tenant": {
                    "alias": tenant_alias,
                    "user_id": tu.id,
                    "username": tu.username,
                },
            },
            status=200,
        )

# class LoginView(APIView):
#     authentication_classes = []
#     permission_classes = []

#     def post(self, request):
#         ser = LoginSerializer(data=request.data)
#         if not ser.is_valid():
#             return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

#         username_in = ser.validated_data["username"].strip()
#         password_in = ser.validated_data["password"]

#         row = UserDatabase.objects.filter(username__iexact=username_in).first()
#         if not row:
#             return Response({"code": "user_not_found", "detail": "Username not found."}, status=404)

#         tenant_alias = _ensure_alias_from_row(row)
#         set_current_tenant(tenant_alias)

#         tu = TenantUser.objects.using(tenant_alias).filter(username__iexact=username_in).first()
#         if not tu:
#             return Response({"code": "user_not_found", "detail": "Username not found in tenant DB."}, status=404)
#         if not tu.is_active:
#             return Response({"code": "inactive_user", "detail": "User is inactive."}, status=403)
#         if not check_password(password_in, tu.password):
#             return Response({"code": "invalid_credentials", "detail": "Invalid username/password."}, status=401)

#         # Build permission map for this user in this tenant
#         permissions_map = build_permissions_map(tu, using_alias=tenant_alias)

#         # Issue tokens with permissions embedded
#         access_token = _issue_jwt(
#             user_id=tu.id,
#             username=tu.username,
#             tenant_alias=tenant_alias,
#             minutes=60,
#             extra={"type": "access", "permissions": permissions_map},
# )
#         refresh_token = _issue_refresh_jwt(
#             user_id=tu.id,
#             username=tu.username,
#             tenant_alias=tenant_alias,
#             days=7,
#             extra={"type": "refresh", "permissions": permissions_map},
# )

#         return Response(
#             {
#                 "detail": "Logged in.",
#                 "token_type": "Bearer",
#                 "access_token": access_token,
#                 "refresh_token": refresh_token,
#                 "permissions": permissions_map,   # also returned for convenience
#                 "tenant": {
#                     "alias": tenant_alias,
#                     "user_id": tu.id,
#                     "username": tu.username,
#                 },
#             },
#             status=200,
#         )

# class LoginView(APIView):
#     """
#     POST /api/login/
#     {
#       "username": "Acme_Admin",
#       "password": "secret123"
#     }

#     - Case-insensitive username mapping against master UserDatabase.username
#     - Verifies password against tenant accounts.User
#     - Returns JWT with tenant_alias
#     """
#     authentication_classes = [] 
#     permission_classes = []

#     def post(self, request):
#         ser = LoginSerializer(data=request.data)
#         if not ser.is_valid():
#             return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

#         username_in = ser.validated_data["username"].strip()
#         password_in = ser.validated_data["password"]

#         row = (
#             UserDatabase.objects
#             .filter(username__iexact=username_in)
#             .first()
#         )
#         if not row:
#             return Response(
#                 {"code": "user_not_found", "detail": "Username not found."},
#                 status=status.HTTP_404_NOT_FOUND,
#             )

#         tenant_alias = _ensure_alias_from_row(row)
#         set_current_tenant(tenant_alias)

#         tu = (
#             TenantUser.objects.using(tenant_alias)
#             .filter(username__iexact=username_in)
#             .first()
#         )
#         if not tu:
#             return Response(
#                 {"code": "user_not_found", "detail": "Username not found in tenant DB."},
#                 status=status.HTTP_404_NOT_FOUND,
#             )
#         if not tu.is_active:
#             return Response(
#                 {"code": "inactive_user", "detail": "User is inactive."},
#                 status=status.HTTP_403_FORBIDDEN,
#             )

#         if not check_password(password_in, tu.password):
#             return Response(
#                 {"code": "invalid_credentials", "detail": "Invalid username/password."},
#                 status=status.HTTP_401_UNAUTHORIZED,
#             )

#         token = _issue_jwt(user_id=tu.id, username=tu.username, tenant_alias=tenant_alias)

#         return Response(
#             {
#                 "detail": "Logged in.",
#                 "token_type": "Bearer",
#                 "access_token": token,
#                 "tenant": {
#                     "alias": tenant_alias,
#                     "user_id": tu.id,
#                     "username": tu.username,
#                 },
#             },
#             status=status.HTTP_200_OK,
#         )


class ProvisionTenantWithModulesAPIView(APIView):
    """
    POST /api/provision-with-modules/
    {
      "tenant_username": "acme_admin",
      "modules": ["Setup", "Help Desk", "asset"],
      "pg_superpass": "optional_override",      # optional; falls back to env PG_SUPER_PASS
      "pg_superuser": "postgres",               # optional; default "postgres"
      "db_host": "localhost",                   # optional; default
      "db_port": "5432",                        # optional; default
      "tenant_admin_password": "optional_pw"    # optional; auto-generated if not provided
    }

    Behavior:
    - Validate modules against config.MainModule (by code OR name, case-insensitive).
    - If any valid module exists and tenant DB not yet provisioned: create DB via onboard_client_db_by_username.
    - If already provisioned: NO password reset, just return info.
    """
    authentication_classes = []   # adjust if you want admin-only
    permission_classes = []

    def post(self, request):
        ser = ProvisionTenantModulesSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
        d = ser.validated_data

        tenant_username = d["tenant_username"].strip()
        req_modules = [m.strip() for m in d["modules"] if m and m.strip()]

        if not req_modules:
            return Response({"detail": "modules cannot be empty."}, status=400)

        # Resolve valid modules (match by code OR name, case-insensitive)
        # Build a case-insensitive set for lookup
        want_set = set(m.lower() for m in req_modules)

        qs = MainModule.objects.all().annotate(
            code_ci=Lower("code"),
            name_ci=Lower("name"),
        )

        accepted = []
        for mm in qs:
            if mm.code_ci in want_set or mm.name_ci in want_set:
                accepted.append({"code": mm.code, "name": mm.name})

        accepted_codes = {x["code"].lower() for x in accepted}
        accepted_names = {x["name"].lower() for x in accepted}
        rejected = [
            m for m in req_modules
            if m.lower() not in accepted_codes and m.lower() not in accepted_names
        ]

        if not accepted:
            return Response(
                {
                    "detail": "No valid modules matched MainModule.",
                    "accepted": [],
                    "rejected": rejected,
                },
                status=400,
            )

        # Determine if tenant already provisioned
        existing = UserDatabase.objects.filter(username__iexact=tenant_username).first()
        created = False
        db_payload = None
        tenant_admin_pw = None

        if existing:
            # already provisioned; do not reset anything
            db_payload = {
                "user_id": existing.user_id,
                "username": existing.username,
                "db_name": existing.db_name,
                "db_user": existing.db_user,
                "db_host": existing.db_host,
                "db_port": existing.db_port,
                "db_type": getattr(existing, "db_type", "self_hosted"),
            }
        else:
            # create new tenant DB (uses env fallback for PG_SUPER_PASS)
            pg_superpass = d.get("pg_superpass") or os.environ.get("PG_SUPER_PASS")
            if not pg_superpass:
                env = environ.Env()
                env_path = str(Path(__file__).resolve().parent.parent / ".env")
                if os.path.exists(env_path):
                    environ.Env.read_env(env_path)
                    pg_superpass = os.environ.get("PG_SUPER_PASS")
            if not pg_superpass:
                return Response(
                    {"code": "missing_pg_super_pass", "detail": "PG_SUPER_PASS is required."},
                    status=400,
                )

            # Attempt provisioning
            try:
                db_entry, effective_pw = onboard_client_db_by_username(
                    tenant_username=tenant_username,
                    tenant_admin_password=d.get("tenant_admin_password"),
                    db_host=d.get("db_host", "localhost"),
                    db_port=d.get("db_port", "5432"),
                    pg_superuser=d.get("pg_superuser", "postgres"),
                    pg_superpass=pg_superpass,
                )
                created = True
                tenant_admin_pw = effective_pw
                db_payload = {
                    "user_id": db_entry.user_id,
                    "username": db_entry.username,
                    "db_name": db_entry.db_name,
                    "db_user": db_entry.db_user,
                    "db_host": db_entry.db_host,
                    "db_port": db_entry.db_port,
                    "db_type": getattr(db_entry, "db_type", "self_hosted"),
                }
            except Exception as e:
                # map common conflicts
                msg = str(e)
                if msg == "username_already_provisioned":
                    # race; reload existing
                    row = UserDatabase.objects.filter(username__iexact=tenant_username).first()
                    db_payload = {
                        "user_id": row.user_id,
                        "username": row.username,
                        "db_name": row.db_name,
                        "db_user": row.db_user,
                        "db_host": row.db_host,
                        "db_port": row.db_port,
                        "db_type": getattr(row, "db_type", "self_hosted"),
                    }
                    created = False
                elif msg.startswith("role_exists:") or msg.startswith("database_exists:"):
                    return Response({"code": "conflict", "detail": msg}, status=409)
                else:
                    return Response({"code": "internal_error", "detail": msg}, status=500)

        return Response(
            {
                "detail": "Tenant ready." if not created else "Tenant created.",
                "provisioned": True,
                "already_provisioned": not created,
                "modules": {
                    "accepted": accepted,
                    "rejected": rejected,
                },
                "db_info": db_payload,
                "tenant_admin": (
                    {"username": tenant_username, "initial_password": tenant_admin_pw}
                    if created else None
                ),
            },
            status=201 if created else 200,
        )


# accounts/views.py (imports)
from rest_framework import generics
from accounts.authentication_master import MasterJWTAuthentication
from .permissions import IsStaffOnly
from .serializers import OrganizationCreateSerializer, SiteCreateSerializer
from .models import Organization, Company, Site
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser


class OrgCreateView(ClientScopedMixin, generics.ListCreateAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = OrganizationCreateSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # ⬅️ add this

    def get_queryset(self):
        return Organization.objects.filter(is_deleted=False).order_by("name")
# accounts/views.py
from rest_framework import generics
from accounts.authentication_master import MasterJWTAuthentication
from .permissions import IsStaffOnly
from .models import Company
from .serializers import CompanyCreateUpdateSerializer  # <-- use the new one

class CompanyListCreateView(ClientScopedMixin, generics.ListCreateAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = CompanyCreateUpdateSerializer

    def get_queryset(self):
        qs = Company.objects.filter(is_deleted=False).order_by("name")
        org_id = self.request.query_params.get("organization_id")
        if org_id:
            qs = qs.filter(organization_id=org_id)
        q = self.request.query_params.get("q")
        if q:
            qs = qs.filter(name__icontains=q)
        return qs.select_related("organization", "default_entity", "default_site")

class CompanyDetailView(ClientScopedMixin, generics.RetrieveUpdateAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = CompanyCreateUpdateSerializer
    queryset = Company.objects.filter(is_deleted=False)

# class CompanyCreateView(ClientScopedMixin, generics.ListCreateAPIView):
#     authentication_classes = [MasterJWTAuthentication]
#     permission_classes = [IsStaffOnly]
#     serializer_class = CompanyCreateSerializer
#     def get_queryset(self):
#         qs = Company.objects.filter(is_deleted=False).order_by("name")
#         org_id = self.request.query_params.get("organization_id")
#         if org_id: qs = qs.filter(organization_id=org_id)
#         return qs

class SiteCreateView(ClientScopedMixin, generics.ListCreateAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = SiteCreateSerializer
    def get_queryset(self):
        qs = Site.objects.filter(is_deleted=False).order_by("name")
        company_id = self.request.query_params.get("company_id")
        if company_id: qs = qs.filter(company_id=company_id)
        return qs




# top:
import jwt
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from config.models import Superadmin
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
class AdminLoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        username = (request.data or {}).get("username", "").strip()
        password = (request.data or {}).get("password", "")
        if not username or not password:
            return Response({"detail": "username and password required"}, status=400)

        sa = Superadmin.objects.filter(username__iexact=username, is_active=True).first()
        if not sa:
            return Response({"detail": "admin not found or inactive"}, status=404)

        if not sa.is_staff:
            return Response({"detail": "not a superadmin"}, status=403)

        if not check_password(password, sa.password):
            return Response({"detail": "invalid credentials"}, status=401)

        now = timezone.now()
        payload = {
            "admin_id": sa.id,
            "admin_username": sa.username,
            "is_superadmin": True,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=2)).timestamp()),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        return Response({"token_type": "Bearer", "access_token": token}, status=200)


# accounts/views.py
from .serializers import (
    OrganizationCreateSerializer, SiteCreateSerializer, EntityCreateSerializer
)
from .models import Organization, Company, Site, Entity
from accounts.authentication_master import MasterJWTAuthentication
from .permissions import IsStaffOnly

class EntityCreateView(ClientScopedMixin, generics.ListCreateAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = EntityCreateSerializer

    def get_queryset(self):
        qs = Entity.objects.filter(is_deleted=False).order_by("name")
        org_id = self.request.query_params.get("organization_id")
        comp_id = self.request.query_params.get("company_id")
        if org_id:
            qs = qs.filter(organization_id=org_id)
        if comp_id:
            qs = qs.filter(company_id=comp_id)
        return qs





# accounts/views.py
from rest_framework import generics
from rest_framework.response import Response
from accounts.authentication_master import MasterJWTAuthentication
from .permissions import IsStaffOnly
from .serializers import AssignSiteModulesByIdSerializer
# ... your ClientScopedMixin import ...

class AssignSiteModulesView(ClientScopedMixin, generics.GenericAPIView):
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = AssignSiteModulesByIdSerializer

    def post(self, request, *args, **kwargs):
        # tenant DB is selected by ClientScopedMixin.initial()
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        result = ser.save()
        return Response(result, status=201)





# accounts/views.py
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from accounts.authentication import JWTTenantAuthentication
from .models import Module, Site
from .serializers import ModuleSerializer

class SiteModulesListView(generics.ListAPIView):
    """
    GET /api/site-modules/?site_id=1
    Auth: Bearer token from tenant login
    Returns only modules where is_deleted = False for that site.
    """
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = ModuleSerializer

    def list(self, request, *args, **kwargs):
        site_id = request.query_params.get("site_id")
        if not site_id:
            return Response({"site_id": ["This query parameter is required."]},
                            status=status.HTTP_400_BAD_REQUEST)

        # Make sure the site exists (in this tenant DB)
        if not Site.objects.filter(id=site_id, is_deleted=False).exists():
            return Response({"site_id": ["Site not found."]},
                            status=status.HTTP_404_NOT_FOUND)

        queryset = Module.objects.filter(site_id=site_id, is_deleted=False).order_by("name")
        page = self.paginate_queryset(queryset)
        if page is not None:
            ser = self.get_serializer(page, many=True)
            return self.get_paginated_response(ser.data)

        ser = self.get_serializer(queryset, many=True)
        return Response(ser.data, status=200)




# accounts/views_tenant_acl.py
from rest_framework import generics, status
from rest_framework.response import Response

from accounts.authentication import JWTTenantAuthentication
from accounts.permissions import IsTenantClient
from .serializers import (
    DepartmentSerializer, RoleSerializer, RoleModulePermissionSerializer
)
from .models import Department, Role, RoleModulePermission


class SoftDeleteDestroyMixin:
    """Soft delete if model has is_deleted; else fall back to hard delete."""
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if hasattr(instance, "is_deleted"):
            instance.is_deleted = True
            instance.save(update_fields=["is_deleted"])
            return Response(status=status.HTTP_204_NO_CONTENT)
        return super().destroy(request, *args, **kwargs)



class DepartmentListCreateView(generics.ListCreateAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = DepartmentSerializer

    def get_queryset(self):
        qs = Department.objects.all().order_by("name")
        if "is_deleted" in [f.name for f in Department._meta.fields]:
            qs = qs.filter(is_deleted=False)
        site_id = self.request.query_params.get("site_id")
        if site_id:
            qs = qs.filter(site_id=site_id)
        return qs


class DepartmentDetailView(SoftDeleteDestroyMixin, generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = DepartmentSerializer

    def get_queryset(self):
        qs = Department.objects.all()
        if "is_deleted" in [f.name for f in Department._meta.fields]:
            qs = qs.filter(is_deleted=False)
        return qs



class RoleListCreateView(generics.ListCreateAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = RoleSerializer

    def get_queryset(self):
        qs = Role.objects.select_related("department", "department__site").all().order_by("name")
        if "is_deleted" in [f.name for f in Role._meta.fields]:
            qs = qs.filter(is_deleted=False)
        dept_id = self.request.query_params.get("department_id")
        site_id = self.request.query_params.get("site_id")
        if dept_id:
            qs = qs.filter(department_id=dept_id)
        if site_id:
            qs = qs.filter(department__site_id=site_id)
        return qs


class RoleDetailView(SoftDeleteDestroyMixin, generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = RoleSerializer

    def get_queryset(self):
        qs = Role.objects.select_related("department").all()
        if "is_deleted" in [f.name for f in Role._meta.fields]:
            qs = qs.filter(is_deleted=False)
        return qs



class RoleModulePermissionListCreateView(generics.ListCreateAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = RoleModulePermissionSerializer

    def get_queryset(self):
        qs = RoleModulePermission.objects.select_related(
            "department", "role", "role__department", "module"
        ).all().order_by("role_id", "module_id")
        if "is_deleted" in [f.name for f in RoleModulePermission._meta.fields]:
            qs = qs.filter(is_deleted=False)

        role_id = self.request.query_params.get("role_id")
        dept_id = self.request.query_params.get("department_id")
        module_id = self.request.query_params.get("module_id")
        if role_id:
            qs = qs.filter(role_id=role_id)
        if dept_id:
            qs = qs.filter(department_id=dept_id)
        if module_id:
            qs = qs.filter(module_id=module_id)
        return qs


class RoleModulePermissionDetailView(SoftDeleteDestroyMixin, generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsTenantClient]
    serializer_class = RoleModulePermissionSerializer

    def get_queryset(self):
        qs = RoleModulePermission.objects.select_related("department", "role", "module").all()
        if "is_deleted" in [f.name for f in RoleModulePermission._meta.fields]:
            qs = qs.filter(is_deleted=False)
        return qs
# accounts/views_user_assign.py
# accounts/views_user_assign.py
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from accounts.authentication import JWTTenantAuthentication
from accounts.permissions import IsTenantClient  # only staff can create/update users
from .models import User
from .serializers import UserCreateUpdateAssignSerializer

class TenantUserListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/tenant/users/
    POST /api/tenant/users/  (creates user + sets department/role)
    """
    authentication_classes = [JWTTenantAuthentication]
    serializer_class = UserCreateUpdateAssignSerializer
    queryset = User.objects.all()

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), IsTenantClient()]
        return [IsAuthenticated()]

    def get_queryset(self):
        qs = super().get_queryset()
        # Optional filters
        dep_id = self.request.query_params.get("department_id")
        role_id = self.request.query_params.get("role_id")
        if dep_id:
            qs = qs.filter(department_id=dep_id)
        if role_id:
            qs = qs.filter(role_id=role_id)
        return qs


class TenantUserRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    """
    GET    /api/tenant/users/<id>/
    PATCH  /api/tenant/users/<id>/   (update dept/role and/or other fields)
    """
    authentication_classes = [JWTTenantAuthentication]
    serializer_class = UserCreateUpdateAssignSerializer
    queryset = User.objects.all()

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH"):
            return [IsAuthenticated(), IsTenantClient()]
        return [IsAuthenticated()]








# accounts/views_userdb.py
from rest_framework import generics
from accounts.authentication_master import MasterJWTAuthentication
from .permissions import IsStaffOnly
from config.models import UserDatabase
from .serializers import (
    UserDatabaseReadSerializer, UserDatabaseUpdateSerializer
)

class UserDatabaseListView(generics.ListAPIView):
    """
    GET /api/master/user-dbs/?q=<search>
    """
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    serializer_class = UserDatabaseReadSerializer

    def get_queryset(self):
        qs = UserDatabase.objects.all().order_by("user_id")
        q = self.request.query_params.get("q")
        if q:
            qs = qs.filter(username__icontains=q)
        return qs


class UserDatabaseDetailView(generics.RetrieveUpdateAPIView):
    """
    GET    /api/master/user-dbs/<id>/
    PATCH  /api/master/user-dbs/<id>/   (partial update)
    PUT    /api/master/user-dbs/<id>/   (full update)
    """
    authentication_classes = [MasterJWTAuthentication]
    permission_classes = [IsStaffOnly]
    queryset = UserDatabase.objects.all()

    def get_serializer_class(self):
        if self.request.method in ("PUT", "PATCH"):
            return UserDatabaseUpdateSerializer
        return UserDatabaseReadSerializer





# accounts/views_master_userdb.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from config.models import UserDatabase
from .serializers import UserDatabaseReadSerializer, UserDatabaseUpdateSerializer
from accounts.authentication_internal import InternalTokenAuthentication

class UserDatabaseByUsernameView(APIView):
    """
    GET  /api/master/user-dbs/by-username/<username>/
    PATCH /api/master/user-dbs/by-username/<username>/
    Auth: Internal token
    """
    authentication_classes = [InternalTokenAuthentication]
    permission_classes = []  # internal token is enough

    def get(self, request, username: str):
        row = UserDatabase.objects.filter(username__iexact=username).first()
        if not row:
            return Response({"detail": "UserDatabase not found for that username."}, status=404)
        return Response(UserDatabaseReadSerializer(row).data, status=200)

    def patch(self, request, username: str):
        row = UserDatabase.objects.filter(username__iexact=username).first()
        if not row:
            return Response({"detail": "UserDatabase not found for that username."}, status=404)

        ser = UserDatabaseUpdateSerializer(row, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(UserDatabaseReadSerializer(row).data, status=200)
