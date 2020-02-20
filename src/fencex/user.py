from fastapi import APIRouter, HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.status import HTTP_401_UNAUTHORIZED

from . import config
from .models import User, Identity
from .utils import get_user_id, url_for

mod = APIRouter()


@mod.get("/")
async def user_info(request: Request):
    uid = get_user_id(request)
    user = (
        await Identity.outerjoin(User)
        .select()
        .where(User.id == uid)
        .gino.load(User.load(add_identity=Identity))
        .first()
    )
    if user:
        return dict(
            id=user.id,
            identities=[
                dict(sub=identity.sub, idp=identity.idp, **identity.profile)
                for identity in user.identities
            ],
            **user.profile
        )
    elif request.app.idps:
        if config.DEFAULT_IDP in request.app.idps:
            idp = request.app.idps[config.DEFAULT_IDP]
        else:
            idp = list(request.app.idps.values())[0]
        return RedirectResponse(url_for(request, idp["login_endpoint"]))
    else:
        raise HTTPException(HTTP_401_UNAUTHORIZED, "Login required.")


@mod.get("/logout")
async def logout(request: Request):
    request.session.pop("uid", None)
    return "success"


def init_app(router):
    router.include_router(mod, tags=["Authentication"])
