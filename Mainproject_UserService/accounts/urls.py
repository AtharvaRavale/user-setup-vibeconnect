from django.urls import path
from .views import ManualOnboardByUsernameAPIView,AutoOnboardByUsernameAPIView,TenantUserListCreateView,TenantUserRetrieveUpdateView
from django.conf import settings
from django.conf.urls.static import static
from .views import *


urlpatterns = [
    # path('user-dbs/', UserDatabaseCreateView.as_view(), name='user-database-create'),
    path('manual-onboard/', ManualOnboardByUsernameAPIView.as_view()),

    path('auto-onboard/', AutoOnboardByUsernameAPIView.as_view()),

    path("login/", LoginView.as_view(), name="tenant-login"),
    path("admin/login/", AdminLoginView.as_view()),     


    path("provision-with-modules/", ProvisionTenantWithModulesAPIView.as_view(), name="provision-with-modules"),

              # new
    path("organizations/", OrgCreateView.as_view()),

    path("companies/", CompanyListCreateView.as_view()),
    path("companies/<int:pk>/", CompanyDetailView.as_view()),    
    path("entities/", EntityCreateView.as_view()),

    path("sites/", SiteCreateView.as_view()),
    path("sites/modules/assign/", AssignSiteModulesView.as_view(), name="assign-site-modules"),
    path("site-modules/", SiteModulesListView.as_view(), name="site-modules"),

    path("departments/", DepartmentListCreateView.as_view(), name="tenant-dept-list-create"),
    path("departments/<int:pk>/", DepartmentDetailView.as_view(), name="tenant-dept-detail"),

    path("roles/", RoleListCreateView.as_view(), name="tenant-role-list-create"),
    path("roles/<int:pk>/", RoleDetailView.as_view(), name="tenant-role-detail"),

    path("role-module-perms/", RoleModulePermissionListCreateView.as_view(), name="tenant-rmp-list-create"),
    path("role-module-perms/<int:pk>/", RoleModulePermissionDetailView.as_view(), name="tenant-rmp-detail"),


    path("tenant/users/", TenantUserListCreateView.as_view(), name="tenant-user-list-create"),
    path("tenant/users/<int:pk>/", TenantUserRetrieveUpdateView.as_view(), name="tenant-user-retrieve-update"),

    # path("master/user-dbs/", UserDatabaseListView.as_view()),
    # path("master/user-dbs/<int:pk>/", UserDatabaseDetailView.as_view()),


    path("master/user-dbs/by-username/<str:username>/", UserDatabaseByUsernameView.as_view()),

]