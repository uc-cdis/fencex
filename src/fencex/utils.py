import uuid

from starlette.datastructures import URLPath
from starlette.requests import Request

from . import config
from .models import User, db


def get_user_id(request: Request):
    uid = request.session.get("uid")
    # noinspection PyBroadException
    try:
        return uuid.UUID(hex=uid)
    except Exception:
        request.session.pop("uid", None)


async def get_user(request: Request, full=True):
    uid = get_user_id(request)
    if uid:
        if full:
            user = await User.get(uid)
        else:
            user = await db.select([User.id]).gino.load(User).first()
        if user:
            return user


def url_for(request: Request, name, **path_params):
    router = request.scope["router"]
    url_path = router.url_path_for(name, **path_params)
    if not config.DEBUG:
        url_path = URLPath(config.URL_PREFIX + url_path)
    return url_path.make_absolute_url(base_url=request.url)


def sanitize_redirect_url(uri, request: Request):
    if uri not in request.app.all_paths:
        uri = url_for(request, "user_info")
    return uri
