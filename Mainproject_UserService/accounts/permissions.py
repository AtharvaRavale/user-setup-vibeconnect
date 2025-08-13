# accounts/permissions.py
from rest_framework.permissions import BasePermission
from config.models import Superadmin

class IsStaffOnly(BasePermission):
    def has_permission(self, request, view):
        u = getattr(request, "user", None)
        return bool(
            u
            and getattr(u, "is_authenticated", False)
            and isinstance(u, Superadmin)
            and getattr(u, "is_staff", False) 
        )



class IsTenantClient(BasePermission):
    message = "Only client users can access this endpoint."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(
            user
            and getattr(user, "is_authenticated", False)
            and getattr(user, "is_client", False)
        )