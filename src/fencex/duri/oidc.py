import logging
from datetime import datetime, timedelta
from uuid import UUID

from authlib.common.urls import add_params_to_uri
from authlib.oauth2 import AuthorizationServer, OAuth2Request, ClientAuthentication
from authlib.oauth2.rfc6749 import (
    InvalidClientError,
    UnauthorizedClientError,
    OAuth2Error,
    AccessDeniedError,
    InvalidRequestError,
)
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc6749.util import extract_basic_authorization
from authlib.oauth2.rfc6750 import (
    BearerTokenValidator as _BearerTokenValidator,
    InvalidTokenError,
    InsufficientScopeError,
)
from authlib.oidc.core import OpenIDCode, UserInfo
from fencex.models import User
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from . import config
from .models import Client, AuthorizationCode, db, BearerToken

log = logging.getLogger(__name__)


class AsyncClientAuthentication(ClientAuthentication):
    def __init__(self, query_client):
        super().__init__(query_client)
        self.register("none", authenticate_none)
        self.register("client_secret_basic", authenticate_client_secret_basic)
        self.register("client_secret_post", authenticate_client_secret_post)

    async def authenticate(self, request, methods):
        for method in methods:
            func = self._methods[method]
            client = await func(self.query_client, request)
            if client:
                request.auth_method = method
                return client

        if "client_secret_basic" in methods:
            raise InvalidClientError(state=request.state, status_code=401)
        raise InvalidClientError(state=request.state)


async def authenticate_client_secret_basic(query_client, request):
    client_id, client_secret = extract_basic_authorization(request.headers)
    if client_id and client_secret:
        client = await _validate_client(query_client, client_id, request.state, 401)
        if client.check_token_endpoint_auth_method(
            "client_secret_basic"
        ) and client.check_client_secret(client_secret):
            log.debug('Authenticate %s via "client_secret_basic" ' "success", client_id)
            return client
    log.debug('Authenticate %s via "client_secret_basic" ' "failed", client_id)


async def authenticate_client_secret_post(query_client, request):
    data = request.form
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    if client_id and client_secret:
        client = await _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method(
            "client_secret_post"
        ) and client.check_client_secret(client_secret):
            log.debug('Authenticate %s via "client_secret_post" ' "success", client_id)
            return client
    log.debug('Authenticate %s via "client_secret_post" ' "failed", client_id)


async def authenticate_none(query_client, request):
    client_id = request.client_id
    if client_id and "client_secret" not in request.data:
        client = await _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method("none"):
            log.debug('Authenticate %s via "none" ' "success", client_id)
            return client
    log.debug('Authenticate {} via "none" ' "failed".format(client_id))


async def _validate_client(query_client, client_id, state=None, status_code=400):
    if client_id is None:
        raise InvalidClientError(state=state, status_code=status_code)

    client = await query_client(client_id)
    if not client:
        raise InvalidClientError(state=state, status_code=status_code)

    return client


class StarletteAuthorizationServer(AuthorizationServer):
    def __init__(self, metadata):
        async def _query_client(client_id):
            try:
                client_id = UUID(client_id)
            except ValueError:
                return None
            else:
                return await Client.get(client_id)

        super().__init__(
            _query_client, None, generate_token=BearerToken.generate, metadata=metadata
        )

    async def create_oauth2_request(self, request: Request):
        if request.method == "POST":
            body = await request.form()
        else:
            body = None

        return OAuth2Request(request.method, str(request.url), body, request.headers)

    def create_json_request(self, request):
        pass

    def handle_response(self, status, body, headers):
        if isinstance(body, dict):
            return JSONResponse(body, status, dict(headers))
        else:
            return Response(body, status, dict(headers))

    async def authenticate_client(self, request, methods):
        if self._client_auth is None and self.query_client:
            self._client_auth = AsyncClientAuthentication(self.query_client)
        return await self._client_auth(request, methods)

    def register_client_auth_method(self, method, func):
        if self._client_auth is None and self.query_client:
            self._client_auth = AsyncClientAuthentication(self.query_client)

        self._client_auth.register(method, func)


class StarletteAuthorizationCodeGrant(AuthorizationCodeGrant):
    async def validate_authorization_request(self):
        client_id = self.request.client_id
        log.debug("Validate authorization request of %r", client_id)

        if client_id is None:
            raise InvalidClientError(state=self.request.state)

        client = await self.server.query_client(client_id)
        if not client:
            raise InvalidClientError(state=self.request.state)

        redirect_uri = self.validate_authorization_redirect_uri(self.request, client)
        response_type = self.request.response_type
        if not client.check_response_type(response_type):
            raise UnauthorizedClientError(
                "The client is not authorized to use "
                '"response_type={}"'.format(response_type),
                state=self.request.state,
                redirect_uri=redirect_uri,
            )

        try:
            self.request.client = client
            self.validate_requested_scope()
            for hook in self._hooks["after_validate_authorization_request"]:
                await hook(self)
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            raise error
        return redirect_uri

    async def create_authorization_response(self, redirect_uri, grant_user):
        state = self.request.state
        if grant_user:
            self.request.user = grant_user

            if hasattr(self, "create_authorization_code"):
                # TODO: deprecate
                code = self.create_authorization_code(
                    self.request.client, grant_user, self.request
                )
            else:
                code = self.generate_authorization_code()
                await self.save_authorization_code(code, self.request)

            params = [("code", code)]
            if state:
                params.append(("state", state))
            uri = add_params_to_uri(redirect_uri, params)
            headers = [("Location", uri)]
            return 302, "", headers

        else:
            raise AccessDeniedError(state=state, redirect_uri=redirect_uri)

    async def validate_token_request(self):
        # ignore validate for grant_type, since it is validated by
        # check_token_endpoint

        # authenticate the client if client authentication is included
        client = await self.authenticate_token_endpoint_client()

        log.debug("Validate token request of %r", client)
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        code = self.request.form.get("code")
        if code is None:
            raise InvalidRequestError('Missing "code" in request.')

        # ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = await self.query_authorization_code(code, client)
        if not authorization_code:
            raise InvalidRequestError('Invalid "code" in request.')

        # validate redirect_uri parameter
        log.debug("Validate token redirect_uri of %r", client)
        redirect_uri = self.request.redirect_uri
        original_redirect_uri = authorization_code.get_redirect_uri()
        if original_redirect_uri and redirect_uri != original_redirect_uri:
            raise InvalidRequestError('Invalid "redirect_uri" in request.')

        # save for create_token_response
        self.request.client = client
        self.request.credential = authorization_code
        self.execute_hook("after_validate_token_request")

    async def authenticate_token_endpoint_client(self):
        client = await self.server.authenticate_client(
            self.request, self.TOKEN_ENDPOINT_AUTH_METHODS
        )
        self.server.send_signal("after_authenticate_client", client=client, grant=self)
        return client

    async def save_authorization_code(self, code, request: OAuth2Request):
        await AuthorizationCode.create(
            code=code,
            client_id=UUID(request.client_id),
            user_id=request.user.id,
            scope=request.scope,
            redirect_uri=request.redirect_uri,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            nonce=request.args.get("nonce"),
        )

    def delete_authorization_code(self, authorization_code):
        pass

    def authenticate_user(self, authorization_code):
        return authorization_code.user

    async def query_authorization_code(self, code, client):
        auth_code = (
            AuthorizationCode.delete.where(AuthorizationCode.code == code)
            .where(AuthorizationCode.client_id == client.client_id)
            .returning(*AuthorizationCode)
            .cte()
            .select()
            .cte()
        )
        return (
            await auth_code.outerjoin(User)
            .select()
            .gino.load(AuthorizationCode.load(user=User))
            .first()
        )

    async def create_token_response(self):
        client = self.request.client
        authorization_code = self.request.credential

        user = self.authenticate_user(authorization_code)
        if not user:
            raise InvalidRequestError('There is no "user" for this code.')

        scope = authorization_code.get_scope()
        token = await self.generate_token(
            client,
            self.GRANT_TYPE,
            user=user,
            scope=client.get_allowed_scope(scope),
            include_refresh_token=client.check_grant_type("refresh_token"),
        )
        log.debug("Issue token %r to %r", token, client)

        self.request.user = user
        self.execute_hook("process_token", token=token)
        self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER


class StarletteOpenIDCode(OpenIDCode):
    async def validate_openid_authorization_request(self, grant):
        nonce = grant.request.data.get("nonce")

        if not nonce:
            if self.require_nonce:
                raise InvalidRequestError('Missing "nonce" in request.')
            return True

        if await self.exists_nonce(nonce, grant.request):
            raise InvalidRequestError("Replay attack")

    async def exists_nonce(self, nonce, request):
        return await db.scalar(
            db.exists().where(AuthorizationCode.nonce == nonce).select()
        )

    def get_jwt_config(self, grant):
        return dict(
            key=config.DURI_PRIVATE_KEY,
            alg=config.DURI_ALGORITHM,
            iss=config.DURI_ISSUER,
            exp=config.DURI_ID_TOKEN_TTL,
        )

    def generate_user_info(self, user, scope):
        return UserInfo(sub=str(user.id), name=user.name)


class BearerTokenValidator(_BearerTokenValidator):
    async def authenticate_token(self, token_string):
        return (
            await BearerToken.outerjoin(User)
            .select()
            .where(BearerToken.access_token == token_string)
            .gino.load(BearerToken.load(user=User))
            .first()
        )

    def request_invalid(self, request):
        pass

    def token_revoked(self, token: BearerToken):
        return token.revoked

    async def __call__(self, token_string, scope, request, scope_operator="AND"):
        if self.request_invalid(request):
            raise InvalidRequestError()
        token = await self.authenticate_token(token_string)
        if not token:
            raise InvalidTokenError(realm=self.realm)
        if self.token_expired(token):
            raise InvalidTokenError(realm=self.realm)
        if self.token_revoked(token):
            raise InvalidTokenError(realm=self.realm)
        if self.scope_insufficient(token, scope, scope_operator):
            raise InsufficientScopeError()
        return token
