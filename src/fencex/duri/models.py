import uuid
from datetime import datetime, timedelta

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.oidc.core import AuthorizationCodeMixin as OIDCCodeMixin
from passlib.hash import argon2
from sqlalchemy.dialects.postgresql import UUID, ARRAY

from . import config
from ..models import db


class Client(db.Model, ClientMixin):
    __tablename__ = "clients"

    client_id = db.Column(UUID(), primary_key=True)
    client_secret = db.Column(db.Unicode())
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    grant_types = db.Column(ARRAY(db.Unicode()), nullable=False)
    response_types = db.Column(ARRAY(db.Unicode()), nullable=False)
    token_endpoint_auth_method = db.Column(db.Unicode(), nullable=False)
    scope = db.Column(db.Unicode(), nullable=False)
    redirect_uris = db.Column(ARRAY(db.Unicode()), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)

    def __init__(self, **values):
        if "client_secret" in values:
            raise ValueError("use refresh_client_secret to set the client_secret")
        super().__init__(**values)

    def refresh_client_secret(self):
        rv = str(uuid.uuid4().hex)
        self.client_secret = argon2.using(rounds=4).hash(rv)
        return rv

    def get_client_id(self):
        return str(self.client_id)

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return argon2.verify(client_secret, self.client_secret)

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        if self.response_types:
            return response_type in self.response_types
        return False

    def check_grant_type(self, grant_type):
        if self.grant_types:
            return grant_type in self.grant_types
        return False


class BearerToken(db.Model, TokenMixin):
    __tablename__ = "bearer_tokens"

    id = db.Column(UUID(), primary_key=True)
    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    scope = db.Column(db.Unicode(), nullable=False)
    access_token = db.Column(db.Unicode(), nullable=False, unique=True, index=True)
    refresh_token = db.Column(db.Unicode(), nullable=False, unique=True, index=True)
    revoked = db.Column(db.Boolean(), nullable=False, default=False)
    issued_at = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime(), nullable=False)

    def get_client_id(self):
        return str(self.client_id)

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return int((self.expires_at - self.issued_at).total_seconds())

    def get_expires_at(self):
        return int(self.expires_at.timestamp())

    @classmethod
    async def generate(
        cls,
        client,
        grant_type,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        access_token = generate_token(42)
        refresh_token = generate_token(48)
        if expires_in is None:
            expires_in = config.DURI_ACCESS_TOKEN_TTL
        now = datetime.utcnow()
        await cls.create(
            id=uuid.uuid4(),
            client_id=client.client_id,
            user_id=user.id,
            scope=scope,
            access_token=access_token,
            refresh_token=refresh_token,
            issued_at=now,
            expires_at=now + timedelta(seconds=expires_in),
        )
        rv = dict(token_type="Bearer", access_token=access_token, expires_in=expires_in)
        if include_refresh_token:
            rv["refresh_token"] = refresh_token
        if scope:
            rv["scope"] = scope
        return rv


class AuthorizationCode(db.Model, OIDCCodeMixin):
    __tablename__ = "authorization_codes"

    code = db.Column(db.Unicode(), primary_key=True)
    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    scope = db.Column(db.Unicode(), nullable=False)
    redirect_uri = db.Column(db.Unicode(), nullable=False)
    expires_at = db.Column(db.DateTime(), nullable=False)
    nonce = db.Column(db.Unicode(), index=True)

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_nonce(self):
        return self.nonce

    def get_auth_time(self):
        return int(self.expires_at.timestamp())


class ClientUser(db.Model):
    __tablename__ = "client_users"

    id = db.Column(UUID(), primary_key=True)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    uniq_user_client = db.UniqueConstraint("user_id", "client_id")
