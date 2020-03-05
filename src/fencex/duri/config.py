from authlib.jose import JsonWebKey, JWK_ALGORITHMS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..config import config

jwk = JsonWebKey(JWK_ALGORITHMS)

DURI_ISSUER = config("DURI_ISSUER", default="https://localhost:8080/user")
DURI_ALGORITHM = config("DURI_ALGORITHM", default="RS256")
DURI_KEY_ALGORITHM = config(
    "DURI_KEY_ALGORITHM", default=dict(RS="RSA", ES="EC").get(DURI_ALGORITHM[:2], "oct")
)
DURI_KEY_ID = config("DURI_KEY_ID", default="FENCEX-SIG")
DURI_PRIVATE_KEY = config(
    "DURI_PRIVATE_KEY",
    cast=lambda x: jwk.dumps(
        x() if callable(x) else x, kty=DURI_KEY_ALGORITHM, use="sig", kid=DURI_KEY_ID
    ),
    default=lambda: rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    .private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    .decode(),
)
DURI_PUBLIC_KEY = config(
    "DURI_PUBLIC_KEY",
    cast=lambda x: jwk.dumps(
        x() if callable(x) else x, kty=DURI_KEY_ALGORITHM, use="sig", kid=DURI_KEY_ID
    ),
    default=lambda: jwk.loads(DURI_PRIVATE_KEY)
    .public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode(),
)
DURI_ACCESS_TOKEN_TTL = config("DURI_ACCESS_TOKEN_TTL", cast=int, default=3600)
DURI_ID_TOKEN_TTL = config("DURI_ID_TOKEN_TTL", cast=int, default=3600)
