#!/usr/bin/env python3
"""Meridian Health dev seed script.

Provisions a complete Meridian Health tenant with realistic data for
development and testing: 350 users, 32 groups, 5 service providers, 3 IdPs.

Usage:
    python ./dev/seed_dev.py

Idempotent: safe to re-run. Skips resources that already exist.
"""

import logging
import random
import sys

import database
import utils.password
import utils.saml
from dev.tenants import provision_tenant
from services.groups.idp import create_idp_base_group
from settings import IS_DEV

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEV_PASSWORD = "DevSeed123!"
SUBDOMAIN = "meridian-health"
TENANT_NAME = "Meridian Health"
EMAIL_DOMAIN = "meridian-health.dev"
BASE_URL = f"https://{SUBDOMAIN}.weftid.localhost"

ATTRIBUTE_MAPPING = {
    "email": "email",
    "first_name": "firstName",
    "last_name": "lastName",
}

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael",
    "Linda", "William", "Barbara", "David", "Elizabeth", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Christopher",
    "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Margaret",
    "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly", "Paul",
    "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth", "Dorothy",
    "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa", "Edward",
    "Deborah", "Ronald", "Stephanie", "Timothy", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz",
    "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris",
    "Morales", "Murphy",
]

# Named admin users: (first, last, email, role, dept_key)
ADMIN_USERS = [
    ("Admin", "User", f"admin@{EMAIL_DOMAIN}", "super_admin", "All Staff"),
    ("Clinical", "Admin", f"admin.clinical@{EMAIL_DOMAIN}", "admin", "Clinical Operations"),
    ("Research", "Admin", f"admin.research@{EMAIL_DOMAIN}", "admin", "Research & Innovation"),
    ("IT", "Admin", f"admin.it@{EMAIL_DOMAIN}", "admin", "Information Technology"),
    ("Compliance", "Admin", f"admin.compliance@{EMAIL_DOMAIN}", "admin", "Compliance & Risk"),
    ("Finance", "Admin", f"admin.finance@{EMAIL_DOMAIN}", "admin", "Finance & Accounting"),
    ("HR", "Admin", f"admin.hr@{EMAIL_DOMAIN}", "admin", "Human Resources"),
    ("Executive", "Admin", f"admin.executive@{EMAIL_DOMAIN}", "admin", "Executive Leadership"),
    ("Patient", "Admin", f"admin.patient@{EMAIL_DOMAIN}", "admin", "Patient Services"),
]

# Bulk member distribution: (dept_key, count)
DEPT_BUCKETS = [
    ("Clinical Operations", 60),
    ("Research & Innovation", 45),
    ("Information Technology", 40),
    ("Compliance & Risk", 35),
    ("Finance & Accounting", 40),
    ("Human Resources", 35),
    ("Executive Leadership", 15),
    ("Patient Services", 70),
]

# Group definitions: (name, description)
GROUP_DEFS = [
    # Root
    ("All Staff", "All Meridian Health employees"),
    # Clinical Operations
    ("Clinical Operations", "Clinical care delivery and patient-facing medical operations"),
    ("Emergency Department", "Emergency and acute care services"),
    ("Inpatient Care", "Hospitalized patient care and ward management"),
    ("Outpatient Services", "Scheduled outpatient appointments and procedures"),
    ("Intensive Care Unit", "Critical care and intensive monitoring"),
    # Research & Innovation
    ("Research & Innovation", "Clinical research, innovation, and data science"),
    ("Clinical Trials", "Regulatory-compliant clinical trial coordination"),
    ("Biostatistics & Analytics", "Statistical analysis and outcomes research"),
    ("Medical Informatics", "Healthcare data systems and clinical decision support"),
    # Information Technology
    ("Information Technology", "IT infrastructure, applications, and security"),
    ("Infrastructure & Cloud", "Servers, networking, and cloud platform management"),
    ("Application Support", "Clinical and business application support"),
    ("Cybersecurity", "Security operations, compliance, and incident response"),
    # Compliance & Risk
    ("Compliance & Risk", "Regulatory compliance and enterprise risk management"),
    ("HIPAA & Privacy", "HIPAA compliance, privacy officer functions, and PHI governance"),
    ("Risk Management", "Enterprise risk assessment and mitigation"),
    # Finance & Accounting
    ("Finance & Accounting", "Financial reporting, budgeting, and accounting"),
    ("General Accounting", "Accounts payable, receivable, and general ledger"),
    ("Budget & Planning", "Annual budgeting, forecasting, and financial planning"),
    # Human Resources
    ("Human Resources", "Talent management, benefits, and workforce strategy"),
    ("Talent Acquisition", "Recruiting, onboarding, and workforce planning"),
    ("Benefits & Compensation", "Employee benefits, payroll, and compensation programs"),
    # Executive Leadership
    ("Executive Leadership", "Senior executive leadership team"),
    ("C-Suite", "Chief executive officers and direct reports"),
    ("Board of Directors", "Governing board members and advisors"),
    # Patient Services
    ("Patient Services", "Patient experience, advocacy, and records management"),
    ("Patient Experience", "Patient satisfaction, care coordination, and advocacy"),
    ("Medical Records", "Health information management and records compliance"),
    # Cross-cutting
    ("HIPAA Covered Entities", "Staff with access to protected health information across departments"),
    ("Leadership", "Cross-functional leadership and management team"),
    ("Remote Workers", "Employees working remotely or in hybrid arrangements"),
]

# Parent → child hierarchy edges
HIERARCHY = [
    # All Staff → each dept
    ("All Staff", "Clinical Operations"),
    ("All Staff", "Research & Innovation"),
    ("All Staff", "Information Technology"),
    ("All Staff", "Compliance & Risk"),
    ("All Staff", "Finance & Accounting"),
    ("All Staff", "Human Resources"),
    ("All Staff", "Executive Leadership"),
    ("All Staff", "Patient Services"),
    # Clinical Operations sub-depts
    ("Clinical Operations", "Emergency Department"),
    ("Clinical Operations", "Inpatient Care"),
    ("Clinical Operations", "Outpatient Services"),
    ("Clinical Operations", "Intensive Care Unit"),
    # Research & Innovation sub-depts
    ("Research & Innovation", "Clinical Trials"),
    ("Research & Innovation", "Biostatistics & Analytics"),
    ("Research & Innovation", "Medical Informatics"),
    # Information Technology sub-depts
    ("Information Technology", "Infrastructure & Cloud"),
    ("Information Technology", "Application Support"),
    ("Information Technology", "Cybersecurity"),
    # Compliance & Risk sub-depts
    ("Compliance & Risk", "HIPAA & Privacy"),
    ("Compliance & Risk", "Risk Management"),
    # Finance & Accounting sub-depts
    ("Finance & Accounting", "General Accounting"),
    ("Finance & Accounting", "Budget & Planning"),
    # Human Resources sub-depts
    ("Human Resources", "Talent Acquisition"),
    ("Human Resources", "Benefits & Compensation"),
    # Executive Leadership sub-depts
    ("Executive Leadership", "C-Suite"),
    ("Executive Leadership", "Board of Directors"),
    # Patient Services sub-depts
    ("Patient Services", "Patient Experience"),
    ("Patient Services", "Medical Records"),
    # DAG cross-cutting edges
    ("Clinical Operations", "HIPAA Covered Entities"),
    ("Research & Innovation", "HIPAA Covered Entities"),
    ("Patient Services", "HIPAA Covered Entities"),
    ("Executive Leadership", "Leadership"),
]

# Leaf sub-groups per department (for bulk user distribution)
DEPT_TO_LEAF_GROUPS: dict[str, list[str]] = {
    "Clinical Operations": ["Emergency Department", "Inpatient Care", "Outpatient Services", "Intensive Care Unit"],
    "Research & Innovation": ["Clinical Trials", "Biostatistics & Analytics", "Medical Informatics"],
    "Information Technology": ["Infrastructure & Cloud", "Application Support", "Cybersecurity"],
    "Compliance & Risk": ["HIPAA & Privacy", "Risk Management"],
    "Finance & Accounting": ["General Accounting", "Budget & Planning"],
    "Human Resources": ["Talent Acquisition", "Benefits & Compensation"],
    "Executive Leadership": ["C-Suite", "Board of Directors"],
    "Patient Services": ["Patient Experience", "Medical Records"],
}

# Service provider definitions: (name, slug)
SPS = [
    ("Compass Patient Portal", "compass-portal"),
    ("NorthStar HR", "northstar-hr"),
    ("Apex Analytics", "apex-analytics"),
    ("MediFlow EHR", "mediflow"),
    ("AuditBridge Compliance", "auditbridge"),
]

# SP → group access control
SP_GROUP_MAP = {
    "Compass Patient Portal": "Patient Services",
    "NorthStar HR": "Human Resources",
    "Apex Analytics": "Research & Innovation",
    "MediFlow EHR": "Clinical Operations",
    "AuditBridge Compliance": "Compliance & Risk",
}

# Identity provider definitions: (name, slug, domain_to_bind or None)
IDPS = [
    ("Cloudbridge IdP", "cloudbridge-idp", "cloudbridge.example.com"),
    ("Vertex SSO", "vertex-sso", None),
    ("HealthConnect SSO", "healthconnect-sso", None),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_tenant_id(subdomain: str) -> str:
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not tenant:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(tenant["id"])


def _get_existing_emails(tenant_id: str) -> set[str]:
    rows = database.fetchall(tenant_id, "select email from user_emails", {})
    return {row["email"] for row in rows}


def _lookup_user_by_email(tenant_id: str, email: str) -> str | None:
    row = database.fetchone(
        tenant_id,
        """
        select u.id from users u
        join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where ue.email = :email
        """,
        {"email": email},
    )
    return str(row["id"]) if row else None


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_1_tenant(log: logging.Logger) -> str:
    """Provision the Meridian Health tenant."""
    log.info("--- Step 1: Tenant ---")
    provision_tenant(SUBDOMAIN, TENANT_NAME)
    tenant_id = _get_tenant_id(SUBDOMAIN)
    log.info("Tenant ready: %s (%s)", SUBDOMAIN, tenant_id)
    return tenant_id


def step_2_admin_users(
    log: logging.Logger,
    tenant_id: str,
    password_hash: str,
) -> tuple[str, dict[str, str]]:
    """Create named admin and super-admin users.

    Returns (super_admin_id, {dept_key: user_id}).
    """
    log.info("--- Step 2: Admin users ---")
    existing_emails = _get_existing_emails(tenant_id)
    admin_ids: dict[str, str] = {}
    super_admin_id: str | None = None

    for first_name, last_name, email, role, dept_key in ADMIN_USERS:
        if email in existing_emails:
            uid = _lookup_user_by_email(tenant_id, email)
            if uid:
                admin_ids[dept_key] = uid
                if role == "super_admin":
                    super_admin_id = uid
            log.info("Admin exists: %s", email)
            continue

        user = database.fetchone(
            tenant_id,
            """
            insert into users (tenant_id, first_name, last_name, role, password_hash)
            values (:tenant_id, :first_name, :last_name, :role, :password_hash)
            returning id
            """,
            {
                "tenant_id": tenant_id,
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
                "password_hash": password_hash,
            },
        )
        if not user:
            raise RuntimeError(f"Failed to create admin user: {email}")
        uid = str(user["id"])

        database.execute(
            tenant_id,
            """
            insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
            values (:tenant_id, :user_id, :email, true, now())
            """,
            {"tenant_id": tenant_id, "user_id": uid, "email": email},
        )

        existing_emails.add(email)
        admin_ids[dept_key] = uid
        if role == "super_admin":
            super_admin_id = uid
        log.info("Created admin: %s (%s)", email, role)

    if not super_admin_id:
        raise RuntimeError("No super_admin found or created")
    return super_admin_id, admin_ids


def step_3_bulk_users(
    log: logging.Logger,
    tenant_id: str,
    password_hash: str,
    existing_emails: set[str],
) -> dict[str, list[str]]:
    """Create bulk member users distributed across departments.

    Returns {dept_key: [user_id, ...]} for newly created users.
    """
    log.info("--- Step 3: Bulk users ---")
    dept_user_ids: dict[str, list[str]] = {dept: [] for dept, _ in DEPT_BUCKETS}
    created = 0

    for dept_key, count in DEPT_BUCKETS:
        for _ in range(count):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)

            uid: str | None = None
            for attempt in range(10):
                suffix = "" if attempt == 0 else str(attempt)
                email = f"{first_name.lower()}.{last_name.lower()}{suffix}@{EMAIL_DOMAIN}"
                if email not in existing_emails:
                    existing_emails.add(email)
                    try:
                        user = database.fetchone(
                            tenant_id,
                            """
                            insert into users (tenant_id, first_name, last_name, role, password_hash)
                            values (:tenant_id, :first_name, :last_name, 'member', :password_hash)
                            returning id
                            """,
                            {
                                "tenant_id": tenant_id,
                                "first_name": first_name,
                                "last_name": last_name,
                                "password_hash": password_hash,
                            },
                        )
                        if not user:
                            break
                        uid = str(user["id"])
                        database.execute(
                            tenant_id,
                            """
                            insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
                            values (:tenant_id, :user_id, :email, true, now())
                            """,
                            {"tenant_id": tenant_id, "user_id": uid, "email": email},
                        )
                        created += 1
                        if created % 50 == 0:
                            log.info("Progress: %d bulk users created", created)
                    except Exception as e:
                        log.error("Error creating user %s: %s", email, str(e))
                    break

            if uid:
                dept_user_ids[dept_key].append(uid)

    log.info("Bulk user creation complete: %d created", created)
    return dept_user_ids


def step_4_groups(
    log: logging.Logger,
    tenant_id: str,
    super_admin_id: str,
) -> dict[str, str]:
    """Create all groups. Returns {name: group_id}."""
    log.info("--- Step 4: Groups ---")
    groups: dict[str, str] = {}

    for name, description in GROUP_DEFS:
        existing = database.groups.get_weftid_group_by_name(tenant_id, name)
        if existing:
            groups[name] = str(existing["id"])
            log.info("Group exists: %s", name)
            continue

        group = database.groups.create_group(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            name=name,
            description=description,
            group_type="weftid",
            created_by=super_admin_id,
        )
        if not group:
            raise RuntimeError(f"Failed to create group: {name}")
        groups[name] = str(group["id"])
        log.info("Created group: %s", name)

    log.info("Groups ready: %d", len(groups))
    return groups


def step_5_group_hierarchy(
    log: logging.Logger,
    tenant_id: str,
    groups: dict[str, str],
) -> None:
    """Add parent-child hierarchy edges (idempotent via on conflict do nothing)."""
    log.info("--- Step 5: Group relationships ---")
    added = 0

    for parent_name, child_name in HIERARCHY:
        result = database.groups.add_group_relationship(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            parent_group_id=groups[parent_name],
            child_group_id=groups[child_name],
        )
        if result:
            added += 1

    log.info("Group relationships configured (%d new edges)", added)


def step_6_group_memberships(
    log: logging.Logger,
    tenant_id: str,
    groups: dict[str, str],
    super_admin_id: str,
    admin_ids: dict[str, str],
    dept_user_ids: dict[str, list[str]],
) -> None:
    """Assign users to groups."""
    log.info("--- Step 6: Group memberships ---")

    # Super admin → All Staff
    database.groups.bulk_add_group_members(
        tenant_id, tenant_id, groups["All Staff"], [super_admin_id]
    )

    # Dept admins → their dept groups
    for dept_key, uid in admin_ids.items():
        if dept_key in groups:
            database.groups.bulk_add_group_members(
                tenant_id, tenant_id, groups[dept_key], [uid]
            )

    # Relevant admins → cross-cutting groups
    for dept_key, group_name in [
        ("Clinical Operations", "HIPAA Covered Entities"),
        ("Research & Innovation", "HIPAA Covered Entities"),
        ("Patient Services", "HIPAA Covered Entities"),
        ("Executive Leadership", "Leadership"),
    ]:
        if dept_key in admin_ids and group_name in groups:
            database.groups.bulk_add_group_members(
                tenant_id, tenant_id, groups[group_name], [admin_ids[dept_key]]
            )

    # Bulk users → leaf sub-groups (distributed round-robin)
    for dept_key, user_ids in dept_user_ids.items():
        if not user_ids:
            continue
        leaf_names = DEPT_TO_LEAF_GROUPS.get(dept_key, [])
        if not leaf_names:
            database.groups.bulk_add_group_members(
                tenant_id, tenant_id, groups[dept_key], user_ids
            )
            continue

        # Collect per-leaf buckets then batch-insert
        n = len(leaf_names)
        leaf_buckets: dict[str, list[str]] = {name: [] for name in leaf_names}
        for i, uid in enumerate(user_ids):
            leaf_buckets[leaf_names[i % n]].append(uid)

        for leaf_name, leaf_uids in leaf_buckets.items():
            if leaf_uids:
                database.groups.bulk_add_group_members(
                    tenant_id, tenant_id, groups[leaf_name], leaf_uids
                )

    # Remote Workers: ~30 users sampled across departments
    remote_sample: list[str] = []
    for user_ids in dept_user_ids.values():
        remote_sample.extend(user_ids[:5])
    if remote_sample:
        database.groups.bulk_add_group_members(
            tenant_id, tenant_id, groups["Remote Workers"], remote_sample[:30]
        )

    log.info("Group memberships configured")


def step_7_service_providers(
    log: logging.Logger,
    tenant_id: str,
    super_admin_id: str,
) -> dict[str, str]:
    """Create service providers with per-SP signing certificates.

    Returns {sp_name: sp_id}.
    """
    log.info("--- Step 7: Service providers ---")
    sp_ids: dict[str, str] = {}

    for sp_name, slug in SPS:
        entity_id = f"https://{slug}.weftid.localhost/saml/metadata"
        acs_url = f"https://{slug}.weftid.localhost/saml/acs"
        slo_url = f"https://{slug}.weftid.localhost/saml/slo"

        existing = database.fetchone(
            tenant_id,
            "select id from service_providers where name = :name limit 1",
            {"name": sp_name},
        )
        if existing:
            sp_id = str(existing["id"])
            sp_ids[sp_name] = sp_id
            log.info("SP exists: %s", sp_name)
        else:
            sp = database.service_providers.create_service_provider(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                name=sp_name,
                entity_id=entity_id,
                acs_url=acs_url,
                slo_url=slo_url,
                created_by=super_admin_id,
                trust_established=True,
            )
            if not sp:
                raise RuntimeError(f"Failed to create SP: {sp_name}")
            sp_id = str(sp["id"])
            sp_ids[sp_name] = sp_id
            log.info("Created SP: %s (id=%s)", sp_name, sp_id)

        # Per-SP signing certificate
        existing_cert = database.sp_signing_certificates.get_signing_certificate(
            tenant_id, sp_id
        )
        if not existing_cert:
            cert_pem, key_pem = utils.saml.generate_sp_certificate(tenant_id)
            encrypted_key = utils.saml.encrypt_private_key(key_pem)
            expires_at = utils.saml.get_certificate_expiry(cert_pem)
            database.sp_signing_certificates.create_signing_certificate(
                tenant_id=tenant_id,
                sp_id=sp_id,
                tenant_id_value=tenant_id,
                certificate_pem=cert_pem,
                private_key_pem_enc=encrypted_key,
                expires_at=expires_at,
                created_by=super_admin_id,
            )
            log.info("Created signing cert for: %s", sp_name)
        else:
            log.info("Signing cert exists for: %s", sp_name)

    return sp_ids


def step_8_sp_group_assignments(
    log: logging.Logger,
    tenant_id: str,
    sp_ids: dict[str, str],
    groups: dict[str, str],
    super_admin_id: str,
) -> None:
    """Assign each SP to its relevant department group."""
    log.info("--- Step 8: SP-group assignments ---")

    for sp_name, group_name in SP_GROUP_MAP.items():
        sp_id = sp_ids[sp_name]
        group_id = groups[group_name]

        existing = database.sp_group_assignments.list_assignments_for_sp(tenant_id, sp_id)
        already_assigned = any(str(a["group_id"]) == group_id for a in existing)

        if not already_assigned:
            database.sp_group_assignments.create_assignment(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                sp_id=sp_id,
                group_id=group_id,
                assigned_by=super_admin_id,
            )
            log.info("Assigned '%s' -> '%s'", sp_name, group_name)
        else:
            log.info("Already assigned: '%s' -> '%s'", sp_name, group_name)


def step_9_identity_providers(
    log: logging.Logger,
    tenant_id: str,
    super_admin_id: str,
) -> None:
    """Create identity providers with base groups and optional domain bindings."""
    log.info("--- Step 9: Identity providers ---")

    for idp_name, slug, domain in IDPS:
        entity_id = f"https://{slug}.example.com/saml/metadata"
        sso_url = f"https://{slug}.example.com/saml/sso"
        sp_entity_id = f"{BASE_URL}/saml/metadata/placeholder-{slug}"

        existing = database.saml.providers.get_identity_provider_by_entity_id(
            tenant_id, entity_id
        )
        if existing:
            idp_id = str(existing["id"])
            log.info("IdP exists: %s", idp_name)
        else:
            idp = database.saml.providers.create_identity_provider(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                name=idp_name,
                provider_type="generic",
                entity_id=entity_id,
                sso_url=sso_url,
                sp_entity_id=sp_entity_id,
                created_by=super_admin_id,
                attribute_mapping=ATTRIBUTE_MAPPING,
                is_enabled=True,
                trust_established=True,
            )
            if not idp:
                raise RuntimeError(f"Failed to create IdP: {idp_name}")
            idp_id = str(idp["id"])
            log.info("Created IdP: %s (id=%s)", idp_name, idp_id)

            create_idp_base_group(
                tenant_id=tenant_id,
                idp_id=idp_id,
                idp_name=idp_name,
            )

        # Domain binding (Cloudbridge IdP only)
        if domain:
            existing_domain = database.fetchone(
                tenant_id,
                "select id from tenant_privileged_domains where domain = :domain",
                {"domain": domain},
            )
            if existing_domain:
                domain_id = str(existing_domain["id"])
                log.info("Privileged domain exists: %s", domain)
            else:
                result = database.fetchone(
                    tenant_id,
                    """
                    insert into tenant_privileged_domains (tenant_id, domain, created_by)
                    values (:tenant_id, :domain, :created_by)
                    returning id
                    """,
                    {"tenant_id": tenant_id, "domain": domain, "created_by": super_admin_id},
                )
                if not result:
                    raise RuntimeError(f"Failed to create privileged domain: {domain}")
                domain_id = str(result["id"])
                log.info("Created privileged domain: %s", domain)

            existing_binding = database.fetchone(
                tenant_id,
                "select id from saml_idp_domain_bindings where domain_id = :domain_id",
                {"domain_id": domain_id},
            )
            if not existing_binding:
                database.execute(
                    tenant_id,
                    """
                    insert into saml_idp_domain_bindings (tenant_id, domain_id, idp_id, created_by)
                    values (:tenant_id, :domain_id, :idp_id, :created_by)
                    """,
                    {
                        "tenant_id": tenant_id,
                        "domain_id": domain_id,
                        "idp_id": idp_id,
                        "created_by": super_admin_id,
                    },
                )
                log.info("Bound domain '%s' to IdP '%s'", domain, idp_name)
            else:
                log.info("Domain binding exists: %s", domain)


def _print_summary(log: logging.Logger, tenant_id: str) -> None:
    user_count = database.fetchone(tenant_id, "select count(*) as n from users", {})
    group_count = database.fetchone(tenant_id, "select count(*) as n from groups", {})
    sp_count = database.fetchone(
        tenant_id, "select count(*) as n from service_providers", {}
    )
    idp_count = database.fetchone(
        tenant_id, "select count(*) as n from saml_identity_providers", {}
    )

    log.info("")
    log.info("=" * 60)
    log.info("Meridian Health Seed Complete")
    log.info("=" * 60)
    log.info("")
    log.info("Tenant:    %s", BASE_URL)
    log.info("Login:     %s/login", BASE_URL)
    log.info("")
    log.info("Users:     %d", user_count["n"] if user_count else 0)
    log.info("Groups:    %d", group_count["n"] if group_count else 0)
    log.info("SPs:       %d", sp_count["n"] if sp_count else 0)
    log.info("IdPs:      %d", idp_count["n"] if idp_count else 0)
    log.info("")
    log.info("Password:  %s  (all users)", DEV_PASSWORD)
    log.info("")
    log.info("Key accounts:")
    log.info("  admin@%s  (super_admin)", EMAIL_DOMAIN)
    log.info("  admin.clinical@%s  (admin)", EMAIL_DOMAIN)
    log.info("  admin.hr@%s  (admin)", EMAIL_DOMAIN)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Seed the Meridian Health dev tenant."""
    if not IS_DEV:
        sys.exit("ERROR: seed_dev.py requires IS_DEV=true. Refusing to run.")

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    log = logging.getLogger("seed_dev")

    log.info("Seeding Meridian Health dev environment...")

    # Hash password once (argon2 is slow; avoid per-user hashing)
    log.info("Hashing password...")
    password_hash = utils.password.hash_password(DEV_PASSWORD)

    tenant_id = step_1_tenant(log)
    super_admin_id, admin_ids = step_2_admin_users(log, tenant_id, password_hash)
    existing_emails = _get_existing_emails(tenant_id)
    dept_user_ids = step_3_bulk_users(log, tenant_id, password_hash, existing_emails)
    groups = step_4_groups(log, tenant_id, super_admin_id)
    step_5_group_hierarchy(log, tenant_id, groups)
    step_6_group_memberships(log, tenant_id, groups, super_admin_id, admin_ids, dept_user_ids)
    sp_ids = step_7_service_providers(log, tenant_id, super_admin_id)
    step_8_sp_group_assignments(log, tenant_id, sp_ids, groups, super_admin_id)
    step_9_identity_providers(log, tenant_id, super_admin_id)
    _print_summary(log, tenant_id)


if __name__ == "__main__":
    main()
