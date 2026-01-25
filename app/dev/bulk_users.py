#!/usr/bin/env python3
import logging
import random

import argh
import database
import utils.password
import utils.validate

# Lists for generating random names
FIRST_NAMES = [
    "James",
    "Mary",
    "John",
    "Patricia",
    "Robert",
    "Jennifer",
    "Michael",
    "Linda",
    "William",
    "Barbara",
    "David",
    "Elizabeth",
    "Richard",
    "Susan",
    "Joseph",
    "Jessica",
    "Thomas",
    "Sarah",
    "Charles",
    "Karen",
    "Christopher",
    "Nancy",
    "Daniel",
    "Lisa",
    "Matthew",
    "Betty",
    "Anthony",
    "Margaret",
    "Mark",
    "Sandra",
    "Donald",
    "Ashley",
    "Steven",
    "Kimberly",
    "Paul",
    "Emily",
    "Andrew",
    "Donna",
    "Joshua",
    "Michelle",
    "Kenneth",
    "Dorothy",
    "Kevin",
    "Carol",
    "Brian",
    "Amanda",
    "George",
    "Melissa",
    "Edward",
    "Deborah",
    "Ronald",
    "Stephanie",
    "Timothy",
    "Rebecca",
    "Jason",
    "Sharon",
    "Jeffrey",
    "Laura",
    "Ryan",
    "Cynthia",
    "Jacob",
    "Kathleen",
    "Gary",
    "Amy",
]

LAST_NAMES = [
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Perez",
    "Thompson",
    "White",
    "Harris",
    "Sanchez",
    "Clark",
    "Ramirez",
    "Lewis",
    "Robinson",
    "Walker",
    "Young",
    "Allen",
    "King",
    "Wright",
    "Scott",
    "Torres",
    "Nguyen",
    "Hill",
    "Flores",
    "Green",
    "Adams",
    "Nelson",
    "Baker",
    "Hall",
    "Rivera",
    "Campbell",
    "Mitchell",
    "Carter",
    "Roberts",
    "Gomez",
    "Phillips",
    "Evans",
    "Turner",
    "Diaz",
    "Parker",
    "Cruz",
    "Edwards",
    "Collins",
    "Reyes",
    "Stewart",
    "Morris",
    "Morales",
    "Murphy",
]


def create_bulk_users(subdomain: str, count: int, password: str):
    """Create multiple test users with random names for a tenant.

    Args:
        subdomain: Tenant subdomain
        count: Number of users to create (max 1000)
        password: Password for all users

    Email addresses are randomly distributed between @acme.com and @example.com domains.
    """
    utils.validate.subdomain(subdomain)

    if count < 1:
        raise ValueError("Count must be at least 1")
    if count > 1000:
        raise ValueError("Count cannot exceed 1000")

    # Get tenant ID from subdomain
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )

    if not tenant:
        raise ValueError(f"Tenant with subdomain {subdomain} not found")

    tenant_id = tenant["id"]

    password_hash = utils.password.hash_password(password)

    # Track used email addresses to avoid duplicates
    used_emails = set()

    # Get existing emails for this tenant
    existing_emails = database.fetchall(
        tenant_id,
        "select email from user_emails",
        {},
    )
    for row in existing_emails:
        used_emails.add(row["email"])

    created_count = 0
    skipped_count = 0

    for i in range(count):
        # Determine role (90% members, 8% admins, 2% super_admins)
        rand = random.random()
        if rand < 0.02:
            role = "super_admin"
        elif rand < 0.10:
            role = "admin"
        else:
            role = "member"

        # Generate random name
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)

        # Randomly select email domain
        domain = random.choice(["acme.com", "example.com"])

        # Generate email address (handle duplicates)
        attempt = 0
        while attempt < 10:
            if attempt == 0:
                email = f"{first_name.lower()}.{last_name.lower()}@{domain}"
            else:
                email = f"{first_name.lower()}.{last_name.lower()}{attempt}@{domain}"

            if email not in used_emails:
                used_emails.add(email)
                break
            attempt += 1
        else:
            # Couldn't find unique email after 10 attempts, skip this user
            logging.warning(
                "Could not generate unique email for %s %s, skipping", first_name, last_name
            )
            skipped_count += 1
            continue

        # Create user
        try:
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
                logging.error("Failed to create user %s", email)
                skipped_count += 1
                continue

            user_id = user["id"]

            # Create email (primary and verified)
            database.execute(
                tenant_id,
                """
                insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
                values (:tenant_id, :user_id, :email, true, now())
                """,
                {"tenant_id": tenant_id, "user_id": user_id, "email": email},
            )

            created_count += 1

            if (created_count + skipped_count) % 100 == 0:
                logging.info("Progress: %d users processed", created_count + skipped_count)

        except Exception as e:
            logging.error("Error creating user %s: %s", email, str(e))
            skipped_count += 1
            continue

    logging.info(
        "Bulk user creation complete: %d created, %d skipped for tenant %s",
        created_count,
        skipped_count,
        subdomain,
    )


if __name__ == "__main__":
    argh.dispatch_command(create_bulk_users)
