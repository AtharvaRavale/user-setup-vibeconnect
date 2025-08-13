from rest_framework import serializers
from config.models import UserDatabase
from .models import Organization, Company, Site, Entity
from django.utils.text import slugify


class UserDatabaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDatabase
        fields = '__all__'


class AutoOnboardByUsernameSerializer(serializers.Serializer):
    tenant_username = serializers.CharField(max_length=150)
    tenant_admin_password = serializers.CharField(max_length=128, required=False, allow_blank=True)
    db_host = serializers.CharField(required=False, default="localhost")
    db_port = serializers.CharField(required=False, default="5432")
    pg_superuser = serializers.CharField(required=False, default="postgres")
    pg_superpass = serializers.CharField(required=False, allow_blank=True, allow_null=True)

class ManualServerOnboardSerializer(serializers.Serializer):
    tenant_username = serializers.CharField(max_length=150)
    pg_superuser = serializers.CharField(required=False, default="postgres")
    pg_superpass = serializers.CharField(required=True)
    db_host = serializers.CharField(required=False, default="localhost")
    db_port = serializers.CharField(required=False, default="5432")
    db_name = serializers.CharField(required=False, allow_blank=True)
    db_user = serializers.CharField(required=False, allow_blank=True)
    tenant_admin_password = serializers.CharField(
        max_length=128, required=False, allow_blank=True
    )

#atharva
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=256, trim_whitespace=False)
    client_username = serializers.CharField(required=False, allow_blank=True)





class ProvisionTenantModulesSerializer(serializers.Serializer):
    tenant_username = serializers.CharField(max_length=150)
    modules = serializers.ListField(
        child=serializers.CharField(max_length=100),
        allow_empty=False
    )
    db_host = serializers.CharField(required=False, default="localhost")
    db_port = serializers.CharField(required=False, default="5432")
    pg_superuser = serializers.CharField(required=False, default="postgres")
    pg_superpass = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    tenant_admin_password = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=128)


class OrganizationCreateSerializer(serializers.ModelSerializer):
    # tenant selector
    client_username  = serializers.CharField(write_only=True)

    # FE names → model fields
    organizationName = serializers.CharField(write_only=True, source="name")
    domainName       = serializers.CharField(write_only=True, required=False, allow_blank=True, source="domain_name")
    subDomainName    = serializers.SlugField(write_only=True, required=False, allow_blank=True, source="subdomain")
    # ⬇️ accept file upload
    organizationLogo = serializers.ImageField(write_only=True, required=False, allow_null=True, source="logo")

    code        = serializers.SlugField(required=False, allow_blank=True)

    # read-only output (so FE gets the URL)
    logo        = serializers.ImageField(read_only=True, source="logo")
    created_at  = serializers.DateTimeField(read_only=True)

    class Meta:
        model  = Organization
        fields = [
            "id", "client_username",
            "organizationName", "domainName", "subDomainName", "organizationLogo",
            "logo", "code", "created_at",
        ]

    def create(self, validated):
        validated.pop("client_username", None)

        if not validated.get("code"):
            base = slugify(validated["name"]) or "org"
            code = base
            i = 1
            while Organization.objects.filter(code=code).exists():
                i += 1
                code = f"{base}-{i}"
            validated["code"] = code

        return Organization.objects.create(**validated)

    def update(self, instance, validated):
        validated.pop("client_username", None)
        return super().update(instance, validated)
    





# accounts/serializers.py
from rest_framework import serializers
from django.utils.text import slugify
from .models import Company, Organization, Entity, Site

class CompanyCreateUpdateSerializer(serializers.ModelSerializer):
    # tenant selector (set by ClientScopedMixin)
    client_username = serializers.CharField(write_only=True)

    # parent link
    organization_id = serializers.IntegerField(write_only=True)

    # FE → model mappings
    companyName   = serializers.CharField(write_only=True, source="name")
    entityId      = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    siteId        = serializers.IntegerField(write_only=True, required=False, allow_null=True)

    solutionType  = serializers.ChoiceField(write_only=True, required=False, allow_blank=True,
                                            choices=[c[0] for c in Company.SOLUTION_TYPE_CHOICES],
                                            source="solution_type")
    # solutionFor   = serializers.ChoiceField(write_only=True, required=False, allow_blank=True,
    #                                         choices=[c[0] for c in Company.SOLUTION_FOR_CHOICES],
    #                                         source="solution_for")
    billingTerm   = serializers.ChoiceField(write_only=True, required=False, allow_blank=True,
                                            choices=[c[0] for c in Company.BILLING_TERM_CHOICES],
                                            source="billing_term")
    billingCycle  = serializers.ChoiceField(write_only=True, required=False, allow_blank=True,
                                            choices=[c[0] for c in Company.BILLING_CYCLE_CHOICES],
                                            source="billing_cycle")
    rateOfBilling = serializers.DecimalField(write_only=True, required=False, allow_null=True,
                                             max_digits=12, decimal_places=2, source="rate_of_billing")
    startDate     = serializers.DateField(write_only=True, required=False, allow_null=True, source="start_date")
    endDate       = serializers.DateField(write_only=True, required=False, allow_null=True, source="end_date")

    country = serializers.CharField(write_only=True, required=False, allow_blank=True)
    state   = serializers.CharField(write_only=True, required=False, allow_blank=True)
    city    = serializers.CharField(write_only=True, required=False, allow_blank=True)
    zone    = serializers.CharField(write_only=True, required=False, allow_blank=True)
    area    = serializers.CharField(write_only=True, required=False, allow_blank=True)
    building= serializers.CharField(write_only=True, required=False, allow_blank=True)
    wing    = serializers.CharField(write_only=True, required=False, allow_blank=True)
    floor   = serializers.CharField(write_only=True, required=False, allow_blank=True)
    unit    = serializers.CharField(write_only=True, required=False, allow_blank=True)
    room    = serializers.CharField(write_only=True, required=False, allow_blank=True)

    # read-only back
    id         = serializers.IntegerField(read_only=True)
    code       = serializers.SlugField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Company
        fields = [
            "id", "client_username", "organization_id",
            "companyName", "entityId", "siteId",
            "solutionType",
            "billingTerm", "rateOfBilling", "billingCycle",
            "startDate", "endDate",
            "country", "state", "city", "zone", "area",
            "building", "wing", "floor", "unit", "room",
            "code", "created_at",
        ]

    def validate(self, attrs):
        # org must exist
        org_id = attrs.get("organization_id")
        if not Organization.objects.filter(id=org_id).exists():
            raise serializers.ValidationError({"organization_id": "Organization not found."})

        # optional entity/site consistency
        ent_id = attrs.get("entityId")
        if ent_id is not None:
            try:
                attrs["_entity_obj"] = Entity.objects.get(id=ent_id)
            except Entity.DoesNotExist:
                raise serializers.ValidationError({"entityId": "Entity not found."})

        site_id = attrs.get("siteId")
        if site_id is not None:
            try:
                attrs["_site_obj"] = Site.objects.get(id=site_id)
            except Site.DoesNotExist:
                raise serializers.ValidationError({"siteId": "Site not found."})

        sd, ed = attrs.get("startDate"), attrs.get("endDate")
        if sd and ed and ed < sd:
            raise serializers.ValidationError({"endDate": "End date cannot be before start date."})
        return attrs

    def create(self, validated):
        validated.pop("client_username", None)
        org_id = validated.pop("organization_id")
        entity = validated.pop("_entity_obj", None)
        site   = validated.pop("_site_obj", None)

        organization = Organization.objects.get(id=org_id)

        # optional explicit code; else model will auto-generate
        if "name" in validated and not validated.get("code"):
            base = slugify(validated["name"]) or "company"
            code = base
            i = 1
            while Company.objects.filter(organization=organization, code=code).exists():
                i += 1
                code = f"{base}-{i}"
            validated["code"] = code

        obj = Company.objects.create(
            organization=organization,
            default_entity=entity,
            default_site=site,
            **validated
        )
        return obj

    def update(self, instance, validated):
        validated.pop("client_username", None)
        validated.pop("organization_id", None)
        entity = validated.pop("_entity_obj", None)
        site   = validated.pop("_site_obj", None)
        if entity is not None:
            instance.default_entity = entity
        if site is not None:
            instance.default_site = site
        return super().update(instance, validated)

# class CompanyCreateSerializer(serializers.ModelSerializer):
#     client_username = serializers.CharField(write_only=True)
#     organization_id = serializers.IntegerField(write_only=True)

#     class Meta:
#         model = Company
#         fields = ["id", "client_username", "name", "organization_id"]

#     def create(self, validated):
#         validated.pop("client_username", None)
#         org_id = validated.pop("organization_id")
#         try:
#             org = Organization.objects.get(id=org_id)
#         except Organization.DoesNotExist:
#             raise serializers.ValidationError({"organization_id": "Organization not found."})
#         return Company.objects.create(organization=org, **validated)


# accounts/serializers.py
from rest_framework import serializers
from django.utils.text import slugify
from .models import Organization, Company, Entity, Site

class EntityCreateSerializer(serializers.ModelSerializer):
    client_username = serializers.CharField(write_only=True)
    organization_id = serializers.IntegerField(required=False, write_only=True)
    company_id = serializers.IntegerField(required=False, write_only=True)
    code = serializers.SlugField(required=False, allow_blank=True)

    class Meta:
        model = Entity
        fields = ["id", "client_username", "name", "code", "organization_id", "company_id"]

    def validate(self, attrs):
        # at least org or company required
        if not attrs.get("organization_id") and not attrs.get("company_id"):
            raise serializers.ValidationError(
                {"non_field_errors": ["Provide either organization_id or company_id."]}
            )
        return attrs

    def create(self, validated):
        validated.pop("client_username", None)
        org_id = validated.pop("organization_id", None)
        comp_id = validated.pop("company_id", None)

        organization = None
        company = None

        if comp_id:
            try:
                company = Company.objects.get(id=comp_id)
            except Company.DoesNotExist:
                raise serializers.ValidationError({"company_id": "Company not found."})
            organization = company.organization

        if org_id:
            try:
                org_obj = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                raise serializers.ValidationError({"organization_id": "Organization not found."})
            if organization and org_obj.id != organization.id:
                raise serializers.ValidationError({"organization_id": "organization_id must match company.organization"})
            organization = organization or org_obj

        # code uniqueness per organization
        if not validated.get("code"):
            base = slugify(validated["name"]) or "entity"
            code = base
            i = 1
            while Entity.objects.filter(organization=organization, code=code).exists():
                i += 1
                code = f"{base}-{i}"
            validated["code"] = code

        return Entity.objects.create(
            organization=organization,
            company=company,
            **validated
        )

# accounts/serializers.py  (replace your SiteCreateSerializer with this)
class SiteCreateSerializer(serializers.ModelSerializer):
    client_username = serializers.CharField(write_only=True)

    # Accept any one of these (at least one required)
    organization_id = serializers.IntegerField(required=False, write_only=True)
    company_id = serializers.IntegerField(required=False, write_only=True)
    entity_id = serializers.IntegerField(required=False, write_only=True)

    entity_name = serializers.CharField(required=False, allow_blank=True)
    code = serializers.SlugField(required=False, allow_blank=True)

    class Meta:
        model = Site
        fields = [
            "id", "client_username", "name", "code", "address",
            "organization_id", "company_id", "entity_id",
            "entity_name",
        ]

    def validate(self, attrs):
        if not attrs.get("organization_id") and not attrs.get("company_id") and not attrs.get("entity_id"):
            raise serializers.ValidationError(
                {"non_field_errors": ["Provide at least one of organization_id, company_id, or entity_id."]}
            )
        return attrs

    def create(self, validated):
        validated.pop("client_username", None)
        org_id = validated.pop("organization_id", None)
        comp_id = validated.pop("company_id", None)
        ent_id = validated.pop("entity_id", None)
        entity_name = validated.pop("entity_name", "").strip()

        organization = None
        company = None
        entity = None

        # Resolve from entity_id first (most specific)
        if ent_id:
            try:
                entity = Entity.objects.get(id=ent_id)
            except Entity.DoesNotExist:
                raise serializers.ValidationError({"entity_id": "Entity not found."})
            organization = entity.organization
            company = entity.company

        # Then resolve company if provided (and ensure consistency)
        if comp_id:
            try:
                c = Company.objects.get(id=comp_id)
            except Company.DoesNotExist:
                raise serializers.ValidationError({"company_id": "Company not found."})
            if organization and c.organization_id != organization.id:
                raise serializers.ValidationError({"company_id": "company.organization must match entity/organization"})
            company = company or c
            organization = organization or c.organization

        # Finally resolve organization if provided (and ensure consistency)
        if org_id:
            try:
                o = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                raise serializers.ValidationError({"organization_id": "Organization not found."})
            if organization and organization.id != o.id:
                raise serializers.ValidationError({"organization_id": "organization must be consistent"})
            organization = organization or o

        # code uniqueness:
        # model enforces unique (company, code). If company is None, we’ll enforce uniqueness per organization.
        if not validated.get("code"):
            base = slugify(validated["name"]) or "site"
            code = base
            i = 1
            # When company exists, enforce (company, code) unique
            if company:
                while Site.objects.filter(company=company, code=code).exists():
                    i += 1
                    code = f"{base}-{i}"
            else:
                # org-level site (no company) — soft enforce uniqueness per org
                while Site.objects.filter(organization=organization, company__isnull=True, code=code).exists():
                    i += 1
                    code = f"{base}-{i}"
            validated["code"] = code

        # Optionally create an entity if entity_name is provided and we don’t already have one
        entity_obj = entity
        if entity_name and not entity_obj:
            ecode = (slugify(entity_name) or "entity")[:64]
            entity_obj, _ = Entity.objects.get_or_create(
                organization=organization,
                company=company,
                code=ecode,
                defaults={"name": entity_name}
            )

        return Site.objects.create(
            organization=organization,
            company=company,
            entity=entity_obj,
            **validated
        )





from rest_framework import serializers
from .models import Site, Module
from config.models import MainModule

class AssignSiteModulesByIdSerializer(serializers.Serializer):
    client_username  = serializers.CharField(write_only=True)
    site_id    = serializers.IntegerField(write_only=True)
    module_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=False
    )
    replace    = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs):
        # site must exist in tenant DB
        try:
            attrs["_site_obj"] = Site.objects.get(id=attrs["site_id"])
        except Site.DoesNotExist:
            raise serializers.ValidationError({"site_id": "Site not found."})

        ids = list(dict.fromkeys(attrs["module_ids"]))  # de-dup, keep order
        mains = list(MainModule.objects.filter(id__in=ids, is_deleted=False))
        found_ids = {m.id for m in mains}
        missing = [str(mid) for mid in ids if mid not in found_ids]
        if missing:
            raise serializers.ValidationError({"module_ids": f"Unknown module ids: {', '.join(missing)}"})

        # keep in same order as requested
        mm_by_id = {m.id: m for m in mains}
        attrs["_main_modules"] = [mm_by_id[mid] for mid in ids]
        return attrs

    def create(self, validated):
        site: Site = validated.pop("_site_obj")
        mains = validated.pop("_main_modules")
        replace = validated.get("replace", False)

        created_or_kept = []
        for mm in mains:
            mod, _ = Module.objects.get_or_create(
                site=site,
                code=mm.code,                 # unique (site, code)
                defaults={"name": mm.name}
            )
            # keep tenant name synced with master
            if mod.name != mm.name:
                mod.name = mm.name
                mod.save(update_fields=["name"])
            created_or_kept.append({"id": mod.id, "code": mod.code, "name": mod.name})

        if replace:
            Module.objects.filter(site=site).exclude(code__in=[m.code for m in mains]).update(is_deleted=True)

        return {
            "site_id": site.id,
            "modules": created_or_kept,
            "replaced": bool(replace),
        }





#atharva
# accounts/serializers.py
from rest_framework import serializers
from .models import Module

class ModuleSerializer(serializers.ModelSerializer):
    site_id = serializers.IntegerField(source="site.id", read_only=True)

    class Meta:
        model = Module
        fields = ["id", "code", "name", "site_id"]




# accounts/serializers_tenant_acl.py
from rest_framework import serializers
from rest_framework.validators import UniqueTogetherValidator
from .models import Department, Role, RoleModulePermission, Site, Module

class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ["id", "site", "name"]
        validators = [
            UniqueTogetherValidator(
                queryset=Department.objects.all(),
                fields=["site", "name"],
                message="Department with this name already exists for this site."
            )
        ]

    def validate_site(self, site):
        if not site:
            raise serializers.ValidationError("site is required")
        if hasattr(site, "is_deleted") and site.is_deleted:
            raise serializers.ValidationError("Site is deleted")
        return site


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "department", "name"]
        validators = [
            UniqueTogetherValidator(
                queryset=Role.objects.all(),
                fields=["department", "name"],
                message="Role with this name already exists in this department."
            )
        ]

    def validate_department(self, dept):
        if not dept:
            raise serializers.ValidationError("department is required")
        if hasattr(dept, "is_deleted") and dept.is_deleted:
            raise serializers.ValidationError("Department is deleted")
        return dept


class RoleModulePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RoleModulePermission
        fields = [
            "id", "department", "role", "module",
            "for_all", "can_view", "can_create", "can_update", "can_delete",
        ]
        validators = [
            UniqueTogetherValidator(
                queryset=RoleModulePermission.objects.all(),
                fields=["role", "module"],
                message="Permissions for this role + module already exist."
            )
        ]

    def validate(self, attrs):
        dept = attrs.get("department") or (self.instance and self.instance.department)
        role = attrs.get("role") or (self.instance and self.instance.role)
        module = attrs.get("module") or (self.instance and self.instance.module)

        if not (dept and role and module):
            raise serializers.ValidationError("department, role and module are required")

        if role.department_id != dept.id:
            raise serializers.ValidationError({"department": "Role.department must match department"})

        for obj, name in ((dept, "department"), (role, "role"), (module, "module")):
            if hasattr(obj, "is_deleted") and obj.is_deleted:
                raise serializers.ValidationError({name: f"{name.capitalize()} is deleted"})

        return attrs

# accounts/serializers_user_assign.py
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User, Department, Role

class SimpleDepartmentReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ["id", "name"]

class SimpleRoleReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "name"]

class UserCreateUpdateAssignSerializer(serializers.ModelSerializer):
    # write fields
    password = serializers.CharField(write_only=True, required=False, allow_blank=False)
    department = serializers.PrimaryKeyRelatedField(
        queryset=Department.objects.all(), required=False, allow_null=True
    )
    role = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(), required=False, allow_null=True
    )

    # read helpers
    department_info = SimpleDepartmentReadSerializer(source="department", read_only=True)
    role_info = SimpleRoleReadSerializer(source="role", read_only=True)

    class Meta:
        model = User
        fields = [
            "id", "username", "email", "first_name", "last_name",
            "is_active", "is_staff", "is_client",
            "password",
            "department", "role",
            "department_info", "role_info",
        ]
        extra_kwargs = {
            "username": {"required": False},  # required on create; optional on update
            "is_active": {"required": False},
            "is_staff": {"required": False},
            "is_client": {"required": False},
        }

    def validate(self, attrs):
        dep = attrs.get("department", getattr(self.instance, "department", None))
        rol = attrs.get("role", getattr(self.instance, "role", None))

        # If role is provided but department is not, infer department from role
        if rol and not dep:
            dep = rol.department
            attrs["department"] = dep

        # Block soft-deleted associations (if your models have is_deleted)
        if dep and hasattr(dep, "is_deleted") and dep.is_deleted:
            raise serializers.ValidationError({"department": "Selected department is deleted."})
        if rol and hasattr(rol, "is_deleted") and rol.is_deleted:
            raise serializers.ValidationError({"role": "Selected role is deleted."})

        # Enforce role belongs to department when both are present
        if dep and rol and rol.department_id != dep.id:
            raise serializers.ValidationError({"role": "Selected role does not belong to the selected department."})

        return attrs

    # ----- CREATE -----
    def create(self, validated_data):
        password = validated_data.pop("password", None)
        if not password:
            raise serializers.ValidationError({"password": "This field is required."})

        # Hash password
        validated_data["password"] = make_password(password)

        # Optional default for subusers: make them client users unless explicitly set
        if "is_client" not in validated_data:
            validated_data["is_client"] = True

        instance = User(**validated_data)
        # model-level consistency (if you added clean() on User)
        instance.full_clean()
        instance.save()
        return instance

    # ----- UPDATE (partial supported) -----
    def update(self, instance, validated_data):
        # Password change if provided
        if "password" in validated_data and validated_data["password"]:
            instance.password = make_password(validated_data.pop("password"))

        for field in ["username", "email", "first_name", "last_name",
                      "is_active", "is_staff", "is_client",
                      "department", "role"]:
            if field in validated_data:
                setattr(instance, field, validated_data[field])

        instance.full_clean()
        instance.save()
        return instance








# accounts/serializers_userdb.py
from rest_framework import serializers
from config.models import UserDatabase
from accounts.utils import encrypt_password

class UserDatabaseReadSerializer(serializers.ModelSerializer):
    db_password_encrypted = serializers.CharField(source="db_password", read_only=True)

    class Meta:
        model = UserDatabase
        fields = [
            "id", "user_id", "username",
            "db_name", "db_user", "db_host", "db_port", "db_type",
            "db_password_encrypted",
        ]


class UserDatabaseUpdateSerializer(serializers.ModelSerializer):
    # Optional plain password setter — will be stored encrypted
    db_password_plain = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = UserDatabase
        fields = ["db_name", "db_user", "db_host", "db_port", "db_type", "db_password_plain"]

    def update(self, instance, validated_data):
        pw_plain = validated_data.pop("db_password_plain", None)

        for attr, val in validated_data.items():
            setattr(instance, attr, val)

        if pw_plain is not None and pw_plain != "":
            instance.db_password = encrypt_password(pw_plain)

        instance.save()

        # drop the runtime alias so next use re-binds with new creds
        from django.conf import settings
        from django.db import connections
        alias = f"client_{instance.user_id}"
        settings.DATABASES.pop(alias, None)
        connections.databases.pop(alias, None)

        return instance
