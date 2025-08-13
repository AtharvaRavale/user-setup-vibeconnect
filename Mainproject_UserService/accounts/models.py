from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify


class User(models.Model):
    username    = models.CharField(max_length=150, unique=True)
    email       = models.EmailField(blank=True, null=True)
    password    = models.CharField(max_length=256)  
    first_name  = models.CharField(max_length=150, blank=True, null=True)
    last_name   = models.CharField(max_length=150, blank=True, null=True)
    is_active   = models.BooleanField(default=True)
    is_staff    = models.BooleanField(default=False)
    is_superuser= models.BooleanField(default=False)
    is_client   = models.BooleanField(default=False)

    is_deleted  = models.BooleanField(default=False)  # <-- NEW FIELD
    deleted_at  = models.DateTimeField(blank=True, null=True)  # <-- Track delete time

    department = models.ForeignKey(
        'accounts.Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
    )

    role = models.ForeignKey(
        'accounts.Role',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
    )

    def clean(self):
        if self.role and self.department and self.role.department_id != self.department_id:
            raise ValidationError({"role": "Selected role does not belong to the selected department."})

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=["is_deleted", "deleted_at"])

    def hard_delete(self, using=None, keep_parents=False):
        super().delete(using=using, keep_parents=keep_parents)

    def __str__(self):
        return self.username


class TenantSoftDeleteModel(models.Model):
    """
    Tenant-side base model.
    IMPORTANT: Do NOT use settings.AUTH_USER_MODEL here (that points to master).
    """
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)
    created_by = models.ForeignKey(
        'accounts.User',                 # tenant user
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_created"
    )

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=["is_deleted", "deleted_at"])

    def hard_delete(self, using=None, keep_parents=False):
        super().delete(using=using, keep_parents=keep_parents)


class Organization(TenantSoftDeleteModel):
    name  = models.CharField(max_length=200, unique=True)
    code  = models.SlugField(max_length=64, unique=True)
    user  = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    domain_name = models.CharField(max_length=120, null=True, blank=True)
    subdomain   = models.SlugField(max_length=64, null=True, blank=True)

    # ⬇️ changed from URL to ImageField
    logo        = models.ImageField(upload_to="org_logo/", null=True, blank=True)

    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["code"])]

    def __str__(self):
        return self.name


class Company(TenantSoftDeleteModel):
    organization = models.ForeignKey(
        Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="companies"
    )
    name = models.CharField(max_length=200)
    code = models.SlugField(max_length=64, blank=True)  # auto from name if empty
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    # Optional default anchors selected in the wizard
    default_entity = models.ForeignKey(
        'accounts.Entity', on_delete=models.SET_NULL, null=True, blank=True, related_name='default_for_companies'
    )
    default_site = models.ForeignKey(
        'accounts.Site', on_delete=models.SET_NULL, null=True, blank=True, related_name='default_for_companies'
    )

    # Solution / billing
    SOLUTION_TYPE_CHOICES = [
        ('white_label', 'White Label'),
        ('standard', 'Standard'),
    ]
    solution_type   = models.CharField(max_length=20, choices=SOLUTION_TYPE_CHOICES, blank=True)

    # SOLUTION_FOR_CHOICES = [
    #     ('vibe_connect', 'Vibe Connect'),
    #     ('my_city_life', 'My City.Life'),
    #     ('construct', 'Construct'),
    #     ('vibe_copilot', 'Vibe Copilot'),
    #     ('e_vidyarthi', 'E Vidyarthi'),
    #     ('lets_sync', 'Let\'s Sync'),
    #     ('hrms', 'HRMS'),
    # ]
    # solution_for    = models.CharField(max_length=20, choices=SOLUTION_FOR_CHOICES, blank=True)

    BILLING_TERM_CHOICES = [
        ('fixed', 'Fixed'),
        ('per_site', 'Per Site'),
        ('per_user', 'Per User'),
    ]
    billing_term    = models.CharField(max_length=20, choices=BILLING_TERM_CHOICES, blank=True)

    BILLING_CYCLE_CHOICES = [
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('half_yearly', 'Half Yearly'),
        ('yearly', 'Yearly'),
    ]
    billing_cycle   = models.CharField(max_length=20, choices=BILLING_CYCLE_CHOICES, blank=True)

    rate_of_billing = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    start_date      = models.DateField(null=True, blank=True)
    end_date        = models.DateField(null=True, blank=True)

    # Address granularity
    country  = models.CharField(max_length=80, blank=True)
    state    = models.CharField(max_length=80, blank=True)
    city     = models.CharField(max_length=80, blank=True)
    zone     = models.CharField(max_length=80, blank=True)
    area     = models.CharField(max_length=120, blank=True)
    building = models.CharField(max_length=120, blank=True)
    wing     = models.CharField(max_length=80, blank=True)
    floor    = models.CharField(max_length=80, blank=True)
    unit     = models.CharField(max_length=80, blank=True)
    room     = models.CharField(max_length=80, blank=True)

    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "name"], name="uniq_company_name_per_org"),
            models.UniqueConstraint(fields=["organization", "code"], name="uniq_company_code_per_org"),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "code"]),
        ]

    def clean(self):
        super().clean()
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValidationError({"end_date": "End date cannot be before start date."})

    def save(self, *args, **kwargs):
        if not self.code:
            base = slugify(self.name) or "company"
            code = base
            i = 1
            while Company.objects.filter(organization=self.organization, code=code).exclude(pk=self.pk).exists():
                i += 1
                code = f"{base}-{i}"
            self.code = code
        super().save(*args, **kwargs)

    def __str__(self):
        org_code = self.organization.code if self.organization else "-"
        return f"{org_code} / {self.name}"

# class Company(TenantSoftDeleteModel):
#     organization = models.ForeignKey(
#         Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="companies"
#     )
#     name = models.CharField(max_length=200)
#     user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

#     class Meta:
#         constraints = [
#             models.UniqueConstraint(
#                 fields=["organization", "name"], name="uniq_company_name_per_org"
#             ),
#         ]
#         indexes = [models.Index(fields=["organization", "name"])]

#     def __str__(self):
#         org_code = self.organization.code if self.organization else "-"
#         return f"{org_code} / {self.name}"


class Entity(TenantSoftDeleteModel):
    organization = models.ForeignKey(
        Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="entities"
    )
    company = models.ForeignKey(
        Company, on_delete=models.SET_NULL, null=True, blank=True, related_name="entities"
    )
    name = models.CharField(max_length=200)
    code = models.SlugField(max_length=64)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"], name="uniq_entity_name_per_org"
            ),
            models.UniqueConstraint(
                fields=["organization", "code"], name="uniq_entity_code_per_org"
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "code"]),
        ]

    def __str__(self):
        org_code = self.organization.code if self.organization else "-"
        return f"{org_code} / {self.code}"


class Site(TenantSoftDeleteModel):
    name    = models.CharField(max_length=200)
    code    = models.SlugField(max_length=64)
    address = models.TextField(blank=True, null=True)

    organization = models.ForeignKey(
        Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="sites"
    )
    company = models.ForeignKey(
        Company, on_delete=models.SET_NULL, null=True, blank=True, related_name="sites"
    )
    entity = models.ForeignKey(
        Entity, on_delete=models.SET_NULL, null=True, blank=True, related_name="sites"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["company", "name"], name="uniq_site_name_per_company"
            ),
            models.UniqueConstraint(
                fields=["company", "code"], name="uniq_site_code_per_company"
            ),
        ]
        indexes = [
            models.Index(fields=["company", "name"]),
            models.Index(fields=["company", "code"]),
        ]

    def __str__(self):
        comp = self.company.name if self.company else "-"
        return f"{comp} / {self.code}"


class Module(TenantSoftDeleteModel):
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name="modules")
    code = models.CharField(max_length=50)
    name = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["site", "code"], name="uniq_module_code_per_site")
        ]
        indexes = [models.Index(fields=["site", "code"])]

    def __str__(self):
        return f"{self.site.code if self.site else '-'} :: {self.code} - {self.name}"


class Department(TenantSoftDeleteModel):
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name="departments")
    name = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["site", "name"], name="uniq_department_per_site")
        ]

    def __str__(self):
        return self.name


class Role(TenantSoftDeleteModel):
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name="roles")
    name = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["department", "name"], name="uniq_role_per_department")
        ]

    def __str__(self):
        return f"{self.department.name if self.department else '-'} / {self.name}"


class RoleModulePermission(TenantSoftDeleteModel):
    department = models.ForeignKey(
        Department, on_delete=models.SET_NULL, null=True, blank=True, related_name="role_module_perms"
    )
    role   = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True, related_name="module_perms")
    module = models.ForeignKey(Module, on_delete=models.SET_NULL, null=True, blank=True, related_name="role_perms")

    for_all    = models.BooleanField(default=False)
    can_view   = models.BooleanField(default=False)
    can_create = models.BooleanField(default=False)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["role", "module"], name="uniq_role_module_perm"),
        ]
        indexes = [
            models.Index(fields=["department", "role"]),
            models.Index(fields=["module"]),
        ]

    def clean(self):
        if self.role and self.department and self.role.department_id != self.department_id:
            raise ValidationError("Role.department must match RoleModulePermission.department")

    def __str__(self):
        return f"{self.role or '-'} → {self.module.code if self.module else '-'}"
