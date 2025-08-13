# accounts/permissions_utils.py
from .models import Module, RoleModulePermission

def build_permissions_map(user, using_alias: str) -> dict:
    """
    Returns: {
      "asset":   {"view": True, "add": False, "delete": False, "update": True, "all": False},
      "fnb":     {"view": False, "add": False, "delete": False, "update": False, "all": True},
      ...
    }
    Keys use Module.code (lowercased).
    """
    perms = {}

    # client = full access to all active modules
    if getattr(user, "is_client", False):
        for m in Module.objects.using(using_alias).filter(is_deleted=False):
            perms[m.code.lower()] = {
                "view": True, "add": True, "delete": True, "update": True, "all": True
            }
        return perms

    # non-client: build from RoleModulePermission for user's role
    role = getattr(user, "role", None)
    if not role:
        # no role => no permissions
        return perms

    # fetch all active tenant modules
    modules = {m.id: m for m in Module.objects.using(using_alias).filter(is_deleted=False)}
    # fetch the role’s perms
    rps = (
        RoleModulePermission.objects.using(using_alias)
        .filter(role=role, is_deleted=False, module__in=modules.keys())
        .select_related("module")
    )

    for rp in rps:
        mod = rp.module
        if not mod or mod.is_deleted:
            continue
        perms[mod.code.lower()] = {
            "view":   bool(rp.can_view or rp.for_all),
            "add":    bool(rp.can_create or rp.for_all),
            "delete": bool(rp.can_delete or rp.for_all),
            "update": bool(rp.can_update or rp.for_all),
            "all":    bool(rp.for_all),
        }
    return perms
