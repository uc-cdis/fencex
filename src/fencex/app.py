import asyncio
import inspect

import click
from fastapi import FastAPI, APIRouter
from starlette.middleware.sessions import SessionMiddleware

try:
    from importlib.metadata import entry_points, version
except ImportError:
    from importlib_metadata import entry_points, version

from . import logger, config
from .models import db

router = APIRouter()
login_router = APIRouter()


def get_app():
    app = FastAPI(title="FenceX", version=version("fencex"), debug=config.DEBUG)
    app.idps = {}
    db.init_app(app)
    load_modules(app)
    return app


class ClientDisconnectMiddleware:
    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        loop = asyncio.get_running_loop()
        rv = loop.create_task(self._app(scope, receive, send))
        waiter = None
        cancelled = False
        if scope["type"] == "http":

            def add_close_watcher():
                nonlocal waiter

                async def wait_closed():
                    nonlocal cancelled
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            if not rv.done():
                                cancelled = True
                                rv.cancel()
                            break

                waiter = loop.create_task(wait_closed())

            scope["add_close_watcher"] = add_close_watcher
        try:
            await rv
        except asyncio.CancelledError:
            if not cancelled:
                raise
        if waiter and not waiter.done():
            waiter.cancel()


def load_modules(app=None):
    if app:
        app.add_middleware(ClientDisconnectMiddleware)
        app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)
        all_args = dict(app=app, router=router, login_router=login_router)

    logger.info("Start to load modules.")
    for ep in entry_points()["fencex.modules"]:
        mod = ep.load()
        if app:
            init_app = getattr(mod, "init_app", None)
            if init_app:
                args = []
                for name in inspect.getfullargspec(init_app).args:
                    args.append(all_args[name])
                init_app(*args)
        msg = "Loaded module: "
        logger.info(
            msg + "%s",
            ep.name,
            extra={"color_message": msg + click.style("%s", fg="cyan")},
        )
    if app:
        router.include_router(login_router, prefix="/login")
        app.include_router(router, prefix=config.URL_PREFIX if config.DEBUG else "")
        app.all_paths = set([r.path for r in app.routes])


@router.get("/version")
def get_version():
    return version("fencex")


@router.get("/_status")
async def get_status():
    now = await db.scalar("SELECT now()")
    return dict(status="OK", timestamp=now)
