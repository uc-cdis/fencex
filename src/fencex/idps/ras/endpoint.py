import logging
import uuid

from authlib.oidc.discovery import get_well_known_url
from fastapi import APIRouter
from sqlalchemy import exists, union, bindparam, or_
from sqlalchemy.dialects.postgresql import JSONB, UUID
from starlette.datastructures import QueryParams
from starlette.requests import Request
from starlette.responses import RedirectResponse, HTMLResponse

from . import config
from .. import oauth
from ...models import User, Identity, db
from ...utils import get_user, url_for, sanitize_redirect_url

oauth.register(
    "ras",
    server_metadata_url=get_well_known_url(config.RAS_URI, external=True),
    client_kwargs={"scope": "openid profile email phone address ga4gh_passport_v1"},
)
logger = logging.getLogger(__name__)
mod = APIRouter()
REDIRECT_HTML = """\
<!DOCTYPE HTML>
<html lang="en-US">
    <head>
        <meta charset="UTF-8">
        <title>%(message)s</title>
        <meta http-equiv="refresh" content="0; url=%(target)s">
    </head>
    <body>
        <div>%(message)s</div>
        <div id="redirect" style="display: none">
            If you are not redirected automatically,
            follow this <a href='%(target)s'>link</a>.
        </div>
        <script type="text/javascript">
            window.location.href = "%(target)s";
            setTimeout(function () {{
                document.getElementById("redirect").style.display = "block";
            }}, 3000);
        </script>
    </body>
</html>
"""


@mod.get("/")
async def ras_login(request: Request, redirect: str = None, merge: bool = False):
    redirect = sanitize_redirect_url(redirect, request)
    if not merge:
        user = await get_user(request, full=False)
        if user:
            return RedirectResponse(redirect)

    request.session["redirect"] = redirect
    request.session["merge"] = merge
    return await oauth.ras.authorize_redirect(request, url_for(request, "ras_callback"))


@mod.get("/callback")
async def ras_callback(request: Request, do: bool = False):
    user = await get_user(request, full=False)
    if user and not request.session.get("merge", False):
        return RedirectResponse(
            request.session.pop("redirect", url_for(request, "user_info"))
        )

    if not do:
        args = QueryParams(request.query_params, do=1)
        return HTMLResponse(
            REDIRECT_HTML
            % dict(
                message="Logging in, please wait...",
                target=(url_for(request, "ras_callback") + "?" + str(args)),
            )
        )

    request.session.pop("merge", False)
    token = await oauth.ras.authorize_access_token(request)
    # user = await oauth.ras.parse_id_token(request, token)
    user_info = await oauth.ras.userinfo(token=token)

    profile = dict(user_info)
    sub = profile.pop("sub")

    exist_identity = (
        Identity.update.where(Identity.sub == bindparam("sub_in"))
        .where(Identity.idp == bindparam("idp_in"))
        .values(profile=bindparam("identity_profile", type_=JSONB()))
        .returning(Identity.user_id)
        .cte("exist_identity")
    )
    exist_identity_scalar = db.select([exist_identity.c.user_id]).as_scalar()
    exist_user = (
        User.update.where(
            or_(
                User.id == exist_identity_scalar,
                User.id == bindparam("current_user_id", type_=UUID()),
            )
        )
        .values(profile=User.profile + bindparam("user_profile", type_=JSONB()))
        .returning(*User)
        .cte("exist_user")
    )
    new_user = (
        User.insert()
        .from_select(
            [User.id, User.profile],
            db.select(
                [
                    bindparam("new_user_id", type_=UUID()),
                    bindparam("user_profile", type_=JSONB()),
                ]
            ).where(~exists(db.select([exist_user]))),
        )
        .returning(*User)
        .cte("new_user")
    )
    user_out = union(db.select([new_user]), db.select([exist_user])).cte("user_out")
    new_identity = (
        Identity.insert()
        .from_select(
            [Identity.sub, Identity.idp, Identity.profile, Identity.user_id],
            db.select(
                [
                    bindparam("sub_in"),
                    bindparam("idp_in"),
                    bindparam("identity_profile", type_=JSONB()),
                    user_out.c.id,
                ]
            ).where(~exists(db.select([exist_identity]))),
        )
        .returning(Identity.user_id)
        .cte("new_identity")
    )
    identity = union(db.select([new_identity]), db.select([exist_identity])).alias(
        "identity_out"
    )
    new_user = (
        await db.select([user_out])
        .select_from(identity.outerjoin(user_out))
        .gino.load(User)
        .first(
            current_user_id=user.id if user else None,
            sub_in=sub,
            idp_in="ras",
            user_profile=dict(
                name=profile.get("preferred_username"),
                nih_login_id=profile.get("UserID"),
            ),
            identity_profile=profile,
            new_user_id=uuid.uuid4(),
        )
    )
    request.session["uid"] = new_user.id.hex
    return HTMLResponse(
        REDIRECT_HTML
        % dict(
            message="Redirecting...",
            target=request.session.pop("redirect", url_for(request, "user_info")),
        )
    )


def init_app(app, login_router):
    login_router.include_router(mod, prefix="/ras", tags=["RAS"])
    app.idps["ras"] = dict(login_endpoint="ras_login")
