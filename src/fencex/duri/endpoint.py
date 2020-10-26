from authlib.oauth2 import OAuth2Error, ResourceProtector
from authlib.oauth2.rfc6749 import InvalidGrantError, urlparse
from authlib.oidc.discovery import get_well_known_url, OpenIDProviderMetadata
from fastapi import APIRouter
from starlette.datastructures import URLPath, URL
from starlette.requests import Request
from starlette.responses import RedirectResponse

from . import config
from .oidc import (
    StarletteAuthorizationServer,
    StarletteAuthorizationCodeGrant as CodeGrant,
    StarletteOpenIDCode,
)
from .. import config as app_config
from ..utils import get_user, url_for as app_url_for

mod = APIRouter()
authorization: StarletteAuthorizationServer = None


@mod.get(get_well_known_url("/"))
async def provider_info():
    return authorization.metadata


@mod.get("/oauth/v2/authorize")
async def authorize(
    request: Request, scope: str, response_type: str, client_id: str, redirect_uri: str
):
    user = await get_user(request)
    try:
        req = await authorization.create_oauth2_request(request)
        # req.user = user
        grant: CodeGrant = authorization.get_authorization_grant(req)
        uri = await grant.validate_authorization_request()
        if not user:
            return RedirectResponse(
                URL(
                    app_url_for(
                        request, list(request.app.idps.values())[0]["login_endpoint"]
                    )
                ).include_query_params(redirect=request.url)
            )
        else:
            return authorization.handle_response(
                *(await grant.create_authorization_response(uri, user))
            )
    except OAuth2Error as error:
        return authorization.handle_error_response(request, error)


@mod.post("/oauth/v2/token")
async def token(request: Request):
    req = await authorization.create_oauth2_request(request)
    try:
        grant = authorization.get_token_grant(req)
    except InvalidGrantError as error:
        return authorization.handle_error_response(req, error)

    try:
        await grant.validate_token_request()
        args = await grant.create_token_response()
        return authorization.handle_response(*args)
    except OAuth2Error as error:
        return authorization.handle_error_response(req, error)


@mod.get("/openid/connect/jwks.json")
async def jwks():
    return dict(keys=[config.DURI_PUBLIC_KEY])


@mod.get("/openid/connect/v1/userinfo")
async def userinfo(request: Request):
    ResourceProtector()
    return {"sub": "xxx"}


def url_for(router, name, **path_params):
    url_path = router.url_path_for(name, **path_params)
    url_path = URLPath(app_config.URL_PREFIX + url_path)
    return url_path.make_absolute_url(base_url=config.DURI_ISSUER)


class Metadata(OpenIDProviderMetadata):
    def validate_issuer(self):
        issuer = self.get("issuer")

        #: 1. REQUIRED
        if not issuer:
            raise ValueError('"issuer" is required')

        parsed = urlparse.urlparse(issuer)

        #: 2. uses the "https" scheme
        if not app_config.DEBUG and parsed.scheme != "https":
            raise ValueError('"issuer" MUST use "https" scheme')

        #: 3. has no query or fragment
        if parsed.query or parsed.fragment:
            raise ValueError('"issuer" has no query or fragment')

    def validate_authorization_endpoint(self):
        url = self.get("authorization_endpoint")
        if url:
            if not app_config.DEBUG and not url.startswith("https://"):
                raise ValueError('"authorization_endpoint" MUST use "https" scheme')
            return

        grant_types_supported = set(self.grant_types_supported)
        authorization_grant_types = {"authorization_code", "implicit"}
        if grant_types_supported & authorization_grant_types:
            raise ValueError('"authorization_endpoint" is required')

    def validate_token_endpoint(self):
        grant_types_supported = self.get("grant_types_supported")
        if (
            grant_types_supported
            and len(grant_types_supported) == 1
            and grant_types_supported[0] == "implicit"
        ):
            return

        url = self.get("token_endpoint")
        if not url:
            raise ValueError('"token_endpoint" is required')

        if not app_config.DEBUG and not url.startswith("https://"):
            raise ValueError('"token_endpoint" MUST use "https" scheme')

    def validate_jwks_uri(self):
        jwks_uri = self.get("jwks_uri")
        if jwks_uri is None:
            raise ValueError('"jwks_uri" is required')
        if not app_config.DEBUG and not jwks_uri.startswith("https://"):
            raise ValueError('"jwks_uri" MUST use "https" scheme')


def init_app(router):
    global authorization
    router.include_router(mod, tags=["DURI on OpenID Connect"])
    metadata = Metadata(
        issuer=config.DURI_ISSUER,
        authorization_endpoint=url_for(router, "authorize"),
        token_endpoint=url_for(router, "token"),
        jwks_uri=url_for(router, "jwks"),
        userinfo_endpoint=url_for(router, "userinfo"),
        response_types_supported=["code", "id_token", "token id_token"],
        subject_types_supported=["pairwise"],
        id_token_signing_alg_values_supported=["RS256"],
    )
    metadata.validate()
    authorization = StarletteAuthorizationServer(metadata)
    authorization.register_grant(CodeGrant, [StarletteOpenIDCode()])
