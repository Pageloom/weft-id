"""Client key pairs and ``private_key_jwt`` assertions for tests.

Keys are generated once per test process (2048-bit RSA and P-256 EC, so
PyJWT's minimum key length check never warns).
"""

import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def public_jwk(private_key, kid: str | None) -> dict:
    """The public JWK of a private key, with ``kid`` when given."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    else:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    if kid is not None:
        jwk["kid"] = kid
    return jwk


JWKS = {"keys": [public_jwk(RSA_KEY, "rsa-1"), public_jwk(EC_KEY, "ec-1")]}


def make_assertion(
    client_id: str,
    audience: str | list[str],
    *,
    key=RSA_KEY,
    alg: str = "RS256",
    kid: str | None = "rsa-1",
    **overrides,
) -> str:
    """A signed client assertion. ``overrides`` replace claims; None drops one."""
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 120,
        "jti": uuid.uuid4().hex,
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims, key, algorithm=alg, headers=headers)
