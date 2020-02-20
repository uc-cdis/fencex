import asyncio
import inspect

import click
from fastapi import FastAPI, APIRouter
from sqlalchemy.engine.url import URL
from starlette.middleware.sessions import SessionMiddleware

try:
    from importlib.metadata import entry_points, version
except ImportError:
    from importlib_metadata import entry_points, version

from . import logger, config
from .models import db

app = FastAPI(title="FenceX", version=version("fencex"), debug=config.DEBUG)
app.idps = {}
router = APIRouter()
login_router = APIRouter()


class ClientDisconnectMiddleware:
    def __init__(self, app_):
        self._app = app_

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


def format_engine(engine, color=False):
    if color:
        # noinspection PyProtectedMember
        return "<{classname} max={max} min={min} cur={cur} use={use}>".format(
            classname=click.style(
                engine.raw_pool.__class__.__module__
                + "."
                + engine.raw_pool.__class__.__name__,
                fg="green",
            ),
            max=click.style(repr(engine.raw_pool._maxsize), fg="cyan"),
            min=click.style(repr(engine.raw_pool._minsize), fg="cyan"),
            cur=click.style(
                repr(
                    len(
                        [
                            0
                            for con in engine.raw_pool._holders
                            if con._con and not con._con.is_closed()
                        ]
                    )
                ),
                fg="cyan",
            ),
            use=click.style(
                repr(len([0 for con in engine.raw_pool._holders if con._in_use])),
                fg="cyan",
            ),
        )
    else:
        # noinspection PyProtectedMember
        return "<{classname} max={max} min={min} cur={cur} use={use}>".format(
            classname=engine.raw_pool.__class__.__module__
            + "."
            + engine.raw_pool.__class__.__name__,
            max=engine.raw_pool._maxsize,
            min=engine.raw_pool._minsize,
            cur=len(
                [
                    0
                    for con in engine.raw_pool._holders
                    if con._con and not con._con.is_closed()
                ]
            ),
            use=len([0 for con in engine.raw_pool._holders if con._in_use]),
        )


@app.on_event("startup")
async def setup_database_connection_pool():
    args = dict(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        database=config.DB_DATABASE,
        min_size=config.DB_MIN_SIZE,
        max_size=config.DB_MAX_SIZE,
    )
    args_not_none = [(k, v) for k, v in args.items() if v is not None]
    msg = "Creating database connection pool: "
    logger.info(
        msg + ", ".join(f"{k}={v}" for k, v in args.items() if v is not None),
        extra={
            "color_message": msg
            + ", ".join(
                f"{k}={click.style(repr(v), fg='cyan')}" for k, v in args_not_none
            )
        },
    )
    url_args = dict(
        drivername="asyncpg",
        host=args.pop("host"),
        port=args.pop("port"),
        username=args.pop("user"),
        password=str(config.DB_PASSWORD),
        database=args.pop("database"),
    )
    retries = 0
    while True:
        retries += 1
        # noinspection PyBroadException
        try:
            await db.set_bind(URL(**url_args), **args)
        except Exception:
            if retries < config.DB_CONNECT_RETRIES:
                logger.info("Waiting for the database to start...")
                await asyncio.sleep(1)
            else:
                logger.error("Max retries reached.")
                raise
        else:
            break
    msg = "Database connection pool created: "
    logger.info(
        msg + format_engine(db.bind),
        extra={"color_message": msg + format_engine(db.bind, color=True)},
    )


@app.on_event("shutdown")
async def shutdown_database_connection_pool():
    msg = "Closing database connection pool: "
    logger.info(
        msg + format_engine(db.bind),
        extra={"color_message": msg + format_engine(db.bind, color=True)},
    )
    bind = db.pop_bind()
    await bind.close()
    msg = "Closed database connection pool: "
    logger.info(
        msg + format_engine(bind),
        extra={"color_message": msg + format_engine(bind, color=True)},
    )


def load_extras():
    app.add_middleware(ClientDisconnectMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)

    logger.info("Start to load modules.")
    all_args = dict(app=app, router=router, login_router=login_router)
    for ep in entry_points()["fencex.modules"]:
        mod = ep.load()
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


load_extras()
