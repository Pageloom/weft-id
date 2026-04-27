#!/usr/bin/env python3
import logging
import time

import argh
import database
import psycopg.errors
import utils.validate


def provision_tenant(subdomain: str, name: str, retries=10):
    utils.validate.subdomain(subdomain)
    logging.info("Provisioning tenant %s at %s", name, subdomain)
    try:
        database.execute(
            database.UNSCOPED,
            """
            insert into tenants (subdomain, name)
            values (:subdomain, :name)
            on conflict (subdomain) do nothing
            """,
            {"subdomain": subdomain, "name": name},
        )
    except psycopg.errors.UndefinedTable:
        if retries > 0:
            time.sleep(1)
            provision_tenant(subdomain, name, retries - 1)
        else:
            raise

    # Seed tenant_attribute_config rows for the new tenant. Idempotent --
    # safe to call on existing tenants. Imported lazily because services
    # is not always available at module import time (e.g. when this
    # module is imported by a CLI before the services package is on the
    # path).
    tenant_row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if tenant_row is not None:
        from services.settings.attributes import seed_tenant_attribute_config

        seed_tenant_attribute_config(str(tenant_row["id"]))


if __name__ == "__main__":
    argh.dispatch_command(provision_tenant)
