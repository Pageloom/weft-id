"""Shared settings for the connector's outbound HTTP calls.

Every call still goes through :func:`utils.safe_http.build_safe_client`; this
module only holds what all of them pass to it.
"""

# The OpenID Foundation conformance suite plays the upstream IdP in the RP
# conformance plans. It runs as a docker service on the dev network (a private
# address the SSRF guard would refuse). Dev only: inert when IS_DEV is false,
# and TLS verification is already off in dev through ``dev_base_domain_rewrite``.
DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})
