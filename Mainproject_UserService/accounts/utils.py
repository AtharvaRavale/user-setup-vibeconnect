import os
import string
import random
import psycopg2
from psycopg2 import sql
from pathlib import Path
from django.db.utils import OperationalError as DjangoOperationalError
from psycopg2 import OperationalError as Psycopg2OperationalError
from django.conf import settings
from django.db import connections
import environ
from cryptography.fernet import Fernet

from django.conf import settings
from django.core.management import call_command
from django.db import connections
from django.contrib.auth.hashers import make_password

from config.models import UserDatabase
from accounts.models import User as TenantUser

env = environ.Env()
env_path = str(Path(__file__).resolve().parent.parent / ".env")
if os.path.exists(env_path):
    environ.Env.read_env(env_path)

def _require_env(key: str) -> str:
    val = os.environ.get(key) or env.str(key, default=None)
    if not val:
        raise Exception(f"Missing environment variable: {key}")
    return val

# utils.py (add these helpers near the top)
def _pg_role_exists(cur, role_name: str) -> bool:
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s;", [role_name])
    return cur.fetchone() is not None

def _pg_db_exists(cur, db_name: str) -> bool:
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", [db_name])
    return cur.fetchone() is not None

def _pg_drop_db(cur, db_name: str):
    # Terminate existing connections then drop
    cur.execute("""
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = %s AND pid <> pg_backend_pid();
    """, [db_name])
    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {};").format(sql.Identifier(db_name)))

def _pg_drop_role(cur, role_name: str):
    cur.execute(sql.SQL("DROP ROLE IF EXISTS {};").format(sql.Identifier(role_name)))

def slugify_name(name: str) -> str:
    """
    Make a lowercase, safe string for Postgres identifiers from the tenant username.
    Removes special characters except underscore and dash.
    """
    base = "".join(ch for ch in name if ch.isalnum() or ch in ("_", "-")).lower()
    return base or "tenant"


def encrypt_password(raw_password: str) -> str:
    key = _require_env("DB_ENCRYPTION_KEY").encode()
    f = Fernet(key)
    return f.encrypt(raw_password.encode()).decode()

def decrypt_password(enc_password: str) -> str:
    key = _require_env("DB_ENCRYPTION_KEY").encode()
    f = Fernet(key)
    return f.decrypt(enc_password.encode()).decode()


def random_password(length: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def _add_db_alias(
    alias: str,
    db_name: str,
    db_user: str,
    db_password: str,
    db_host: str,
    db_port: str,
):
    """
    Register a tenant DB alias at runtime so ORM/management commands can use it.
    Includes sane defaults for connection behavior.
    """
    settings.DATABASES[alias] = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": db_name,
        "USER": db_user,
        "PASSWORD": db_password,
        "HOST": db_host,
        "PORT": db_port,

        "OPTIONS": {
        },
        "TIME_ZONE": None,    
        "ATOMIC_REQUESTS": False,     
        "AUTOCOMMIT": True,           
        "CONN_HEALTH_CHECKS": False,  
        "CONN_MAX_AGE": 0,           
    }

    connections.databases[alias] = settings.DATABASES[alias]
import re
from django.db import transaction, connections
from django.db.models import Max
from io import StringIO


def _slugify_db_identifier(s: str) -> str:
    """
    Make a safe postgres identifier from username:
    - lowercase
    - non-alphanumeric -> underscore
    - collapse multiple underscores
    - trim leading/trailing underscores
    """
    s = s.strip().lower()
    s = re.sub(r'[^a-z0-9]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    return s or 'tenant'

def onboard_client_db_by_username(
    *,
    tenant_username: str,
    tenant_admin_password: str | None,
    db_host: str = "localhost",
    db_port: str = "5432",
    pg_superuser: str = "postgres",
    pg_superpass: str | None = None,
):
    """
    Username-only flow:
    - Ensure no existing UserDatabase row for this username (case-insensitive).
    - Pick new user_id = max(user_id) + 1
    - Create PG ROLE/DB based on sanitized username (slug).
    - Create master UserDatabase row (inside atomic).
    - Register runtime alias, migrate 'accounts', create tenant admin user.
    """
    if not pg_superpass:
        pg_superpass = _require_env("PG_SUPER_PASS")
    if not pg_superpass:
        raise Exception("Superuser password not found. Set PG_SUPER_PASS env var.")

    # block duplicates (case-insensitive)
    if UserDatabase.objects.filter(username__iexact=tenant_username).exists():
        raise Exception("username_already_provisioned")

    # next user_id
    max_id = UserDatabase.objects.aggregate(mx=Max("user_id"))["mx"] or 0
    user_id = max_id + 1

    # db/role names from username
    slug = _slugify_db_identifier(tenant_username)
    db_user = f"{slug}"
    db_name = f"{slug}_db"
    db_password = random_password()

    # connect to maintenance DB
    con = psycopg2.connect(
        dbname="postgres",
        user=pg_superuser,
        password=pg_superpass,
        host=db_host,
        port=db_port,
    )
    con.set_session(autocommit=True)
    cur = con.cursor()

    role_created = False
    db_created = False
    db_entry = None
    alias_added = False
    db_alias = f"client_{user_id}"  # runtime alias still tied to new id

    try:
        # pre-existence checks (don’t overwrite)
        if _pg_role_exists(cur, db_user):
            raise Exception(f"role_exists:{db_user}")
        if _pg_db_exists(cur, db_name):
            raise Exception(f"database_exists:{db_name}")

        # create role + db
        cur.execute(
            sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD %s;").format(sql.Identifier(db_user)),
            [db_password],
        )
        role_created = True

        cur.execute(
            sql.SQL("CREATE DATABASE {} OWNER {};").format(sql.Identifier(db_name), sql.Identifier(db_user))
        )
        db_created = True

        # master row + alias + migrate + tenant admin
        with transaction.atomic(using="default"):
            db_entry = UserDatabase.objects.create(
                user_id=user_id,
                username=tenant_username,
                db_name=db_name,
                db_user=db_user,
                db_password=encrypt_password(db_password),
                db_host=db_host,
                db_port=db_port,
            )

            # add alias
            _add_db_alias(
                alias=db_alias,
                db_name=db_name,
                db_user=db_user,
                db_password=db_password,
                db_host=db_host,
                db_port=db_port,
            )
            alias_added = True

            # migrate tenant app(s)
            call_command("migrate", "accounts", database=db_alias, interactive=False, verbosity=1)

            # optional: log migrations
            buf = StringIO()
            call_command("showmigrations", "accounts", database=db_alias, stdout=buf)
            print(f"[{db_alias}] showmigrations:\n{buf.getvalue()}")

            # tenant admin (don’t reset if exists)
            if not tenant_admin_password:
                tenant_admin_password = random_password()
            TenantUser.objects.using(db_alias).get_or_create(
                username=tenant_username,
                defaults={
                    "email": None,
                    "password": make_password(tenant_admin_password),
                    "is_active": True,
                    "is_staff": True,
                    "is_superuser": True,
                    "is_client": True,
                },
            )

            return db_entry, tenant_admin_password  # return initial pw too

    except Exception:
        # cleanup best-effort
        try:
            if alias_added:
                settings.DATABASES.pop(db_alias, None)
                connections.databases.pop(db_alias, None)
        except Exception:
            pass
        try:
            if db_entry:
                db_entry.delete()
        except Exception:
            pass
        try:
            if db_created:
                _pg_drop_db(cur, db_name)
        except Exception:
            pass
        try:
            if role_created:
                _pg_drop_role(cur, db_user)
        except Exception:
            pass
        raise
    finally:
        cur.close()
        con.close()


def manual_onboard_with_server(
    *,
    tenant_username: str,
    pg_superuser: str,
    pg_superpass: str,
    db_host: str = "localhost",
    db_port: str = "5432",
    db_name: str | None = None,
    db_user: str | None = None,
    tenant_admin_password: str | None = None,
):
    # 0) Don’t allow duplicate provisioning for same tenant (case-insensitive)
    if UserDatabase.objects.filter(username__iexact=tenant_username).exists():
        raise Exception("username_already_provisioned")

    # 1) Decide names if not provided
    base = slugify_name(tenant_username)
    db_name = db_name or f"{base}_db"
    db_user = db_user or f"{base}_user"

    # 2) Allocate a new user_id: max + 1
    next_id = (UserDatabase.objects.aggregate(mx=Max("user_id"))["mx"] or 0) + 1
    db_alias = f"client_{next_id}"

    # 3) Connect to maintenance DB
    con = psycopg2.connect(
        dbname="postgres",
        user=pg_superuser,
        password=pg_superpass,
        host=db_host,
        port=db_port,
    )
    con.set_session(autocommit=True)
    cur = con.cursor()

    role_created = False
    db_created = False
    alias_added = False
    db_entry = None

    try:
        # 4) Pre-checks
        if _pg_role_exists(cur, db_user):
            raise Exception(f"role_exists:{db_user}")
        if _pg_db_exists(cur, db_name):
            raise Exception(f"database_exists:{db_name}")

        # 5) Create role + random password for tenant DB user
        tenant_db_password = random_password()
        cur.execute(
            sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD %s;")
               .format(sql.Identifier(db_user)),
            [tenant_db_password],
        )
        role_created = True

        # 6) Create database owned by that role
        cur.execute(
            sql.SQL("CREATE DATABASE {} OWNER {};")
               .format(sql.Identifier(db_name), sql.Identifier(db_user))
        )
        db_created = True

        # 7) Master row + runtime alias + migrate + seed admin (atomic on master)
        with transaction.atomic(using="default"):
            db_entry = UserDatabase.objects.create(
                user_id=next_id,
                username=tenant_username,
                db_name=db_name,
                db_user=db_user,
                db_password=encrypt_password(tenant_db_password),
                db_host=db_host,
                db_port=db_port,
            )

            _add_db_alias(
                alias=db_alias,
                db_name=db_name,
                db_user=db_user,
                db_password=tenant_db_password,
                db_host=db_host,
                db_port=db_port,
            )
            alias_added = True

            # migrate tenant app(s)
            call_command("migrate", "accounts", database=db_alias, interactive=False, verbosity=1)

            # create tenant admin
            if not tenant_admin_password:
                tenant_admin_password = random_password()

            TenantUser.objects.using(db_alias).get_or_create(
                username=tenant_username,
                defaults={
                    "email": None,
                    "password": make_password(tenant_admin_password),
                    "is_active": True,
                    "is_staff": True,
                    "is_superuser": True,
                    "is_client": True,
                },
            )

        # success
        return db_entry, tenant_admin_password, tenant_db_password

    except Exception:
        # rollback side-effects (best-effort)
        try:
            if alias_added:
                settings.DATABASES.pop(db_alias, None)
                connections.databases.pop(db_alias, None)
        except Exception:
            pass
        try:
            if db_created:
                _pg_drop_db(cur, db_name)
        except Exception:
            pass
        try:
            if role_created:
                _pg_drop_role(cur, db_user)
        except Exception:
            pass
        if db_entry:
            try:
                db_entry.delete()
            except Exception:
                pass
        raise
    finally:
        cur.close()
        con.close()



# def onboard_client_db(
#     user_id: int,
#     *,
#     tenant_username: str,
#     tenant_admin_password: str | None,
#     db_host: str = "localhost",
#     db_port: str = "5432",
#     pg_superuser: str = "postgres",
#     pg_superpass: str | None = None,
# ):
#     # 0) Resolve PG super pass as you already do
#     if not pg_superpass:
#         pg_superpass = _require_env("PG_SUPER_PASS")
#     if not pg_superpass:
#         raise Exception("Superuser password not found. Set PG_SUPER_PASS env var.")

#     # 1) App-level idempotency: if we already have a row for this user_id, stop
#     existing = UserDatabase.objects.filter(user_id=user_id).first()
#     if existing:
#         # No mutation, NO password reset — just signal to caller that it's already provisioned.
#         raise Exception(f"user_id {user_id} is already provisioned")

#     db_name = f"client_{user_id}_db"
#     db_user = f"client_{user_id}_user"
#     db_password = random_password()

#     # 2) Connect to postgres (maintenance DB) with autocommit for DDL
#     con = psycopg2.connect(
#         dbname="postgres",
#         user=pg_superuser,
#         password=pg_superpass,
#         host=db_host,
#         port=db_port,
#     )
#     con.set_session(autocommit=True)
#     cur = con.cursor()

#     role_created = False
#     db_created = False
#     db_entry = None
#     alias_added = False

#     try:
#         # 3) Pre-checks: fail fast if role/db already exist (no resets)
#         if _pg_role_exists(cur, db_user):
#             raise Exception(f"Role '{db_user}' already exists")
#         if _pg_db_exists(cur, db_name):
#             raise Exception(f"Database '{db_name}' already exists")

#         # 4) Create role
#         cur.execute(
#             sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD %s;")
#                .format(sql.Identifier(db_user)),
#             [db_password],
#         )
#         role_created = True

#         # 5) Create database owned by that role
#         cur.execute(
#             sql.SQL("CREATE DATABASE {} OWNER {};")
#                .format(sql.Identifier(db_name), sql.Identifier(db_user))
#         )
#         db_created = True

#         # 6) From here on, also keep Django-side in sync using a DB transaction
#         with transaction.atomic(using="default"):
#             db_entry = UserDatabase.objects.create(
#                 user_id=user_id,
#                 username=tenant_username,
#                 db_name=db_name,
#                 db_user=db_user,
#                 db_password=encrypt_password(db_password),
#                 db_host=db_host,
#                 db_port=db_port,
#             )

#             # register alias
#             db_alias = f"client_{user_id}"
#             _add_db_alias(
#                 alias=db_alias,
#                 db_name=db_name,
#                 db_user=db_user,
#                 db_password=db_password,
#                 db_host=db_host,
#                 db_port=db_port,
#             )
#             alias_added = True

#             # migrate tenant app(s)
#             call_command("migrate", "accounts", database=db_alias, interactive=False, verbosity=1)

#             # (optional) log migrations
#             buf = StringIO()
#             call_command("showmigrations", "accounts", database=db_alias, stdout=buf)
#             print(f"[{db_alias}] showmigrations:\n{buf.getvalue()}")

#             # create tenant admin
#             if not tenant_admin_password:
#                 tenant_admin_password = random_password()

#             TenantUser.objects.using(db_alias).get_or_create(
#                 username=tenant_username,
#                 defaults={
#                     "email": None,
#                     "password": make_password(tenant_admin_password),
#                     "is_active": True,
#                     "is_staff": True,
#                     "is_superuser": True,
#                     "is_client": True,
#                 },
#             )

#             # if we reached here, everything is consistent; the atomic block will commit
#             return db_entry

#     except Exception as e:
#         # --- COMPENSATING ACTIONS (best-effort) ---
#         try:
#             if alias_added:
#                 # remove runtime alias to avoid dangling connections
#                 settings.DATABASES.pop(f"client_{user_id}", None)
#                 connections.databases.pop(f"client_{user_id}", None)
#         except Exception:
#             pass

#         try:
#             if db_entry:
#                 # remove meta row from master
#                 db_entry.delete()
#         except Exception:
#             pass

#         try:
#             if db_created:
#                 _pg_drop_db(cur, db_name)
#         except Exception:
#             pass

#         try:
#             if role_created:
#                 _pg_drop_role(cur, db_user)
#         except Exception:
#             pass

#         # re-raise for the view to return 500 (or map to your codes)
#         raise
#     finally:
#         cur.close()
#         con.close()

# def manual_onboard_client_db(
#     user_id: int,
#     *,
#     tenant_username: str,
#     db_name: str,
#     db_user: str,
#     db_password: str,
#     db_host: str,
#     db_port: str = "5432",
#     tenant_admin_password: str | None = None,
# ):
#     """
#     - Validates provided DB creds (connect test) before writing anything.
#     - Creates master metadata row inside an atomic transaction.
#     - Registers runtime alias, migrates tenant apps.
#     - Creates/ensures tenant admin user.
#     - On any error after alias/migrate: removes alias and rolls back the master row.
#     """

#     # 0) Sanity check: can we connect to the provided DB with these creds?
#     try:
#         test_con = psycopg2.connect(
#             dbname=db_name,
#             user=db_user,
#             password=db_password,
#             host=db_host,
#             port=db_port,
#         )
#         test_con.close()
#     except (Psycopg2OperationalError, DjangoOperationalError) as e:
#         raise e

#     db_alias = f"client_{user_id}"
#     alias_added = False

#     with transaction.atomic(using="default"):
#         db_entry = UserDatabase.objects.create(
#             user_id=user_id,
#             username=tenant_username,
#             db_name=db_name,
#             db_user=db_user,
#             db_password=encrypt_password(db_password),
#             db_host=db_host,
#             db_port=db_port,
#         )

#         # 2) Add runtime alias (out-of-DB side effect; we’ll clean it up on failure)
#         _add_db_alias(
#             alias=db_alias,
#             db_name=db_name,
#             db_user=db_user,
#             db_password=db_password,
#             db_host=db_host,
#             db_port=db_port,
#         )
#         alias_added = True

#         try:
#             # 3) Migrate tenant apps on that alias
#             call_command("migrate", "accounts", database=db_alias, interactive=False, verbosity=1)

#             # 4) Create/ensure tenant admin (no password reset if exists)
#             if not tenant_admin_password:
#                 tenant_admin_password = random_password()

#             TenantUser.objects.using(db_alias).get_or_create(
#                 username=tenant_username,
#                 defaults={
#                     "email": None,
#                     "password": make_password(tenant_admin_password),
#                     "is_active": True,
#                     "is_staff": True,
#                     "is_superuser": True,
#                     "is_client": True,
#                 },
#             )
#         except Exception:
#             # remove the alias so we don't leave a dangling connection
#             if alias_added:
#                 settings.DATABASES.pop(db_alias, None)
#                 connections.databases.pop(db_alias, None)
#             # re-raise -> atomic() will roll back the master row
#             raise

#     return db_entry
