#!/usr/bin/env python3
import logging
import time

import argh
import psycopg.errors

import database
import utils.validate


def provision_tenant(subdomain: str, name: str, retries=10) -> bool:
    utils.validate.subdomain(subdomain)
    logging.info("Provisioning tenant %s at %s", name, subdomain)
    try:
        database.execute(
            database.UNSCOPED,
            """
            insert into tenants (subdomain, name)
            values (%(subdomain)s, %(name)s)
            on conflict (subdomain) do nothing
            """,
            {"subdomain": subdomain, "name": name},
        )
        return True
    except psycopg.errors.UndefinedTable:
        if retries > 0:
            time.sleep(1)
            provision_tenant(subdomain, name, retries - 1)
        else:
            raise


if __name__ == "__main__":
    argh.dispatch_command(provision_tenant)
