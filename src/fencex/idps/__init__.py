from authlib.integrations.starlette_client import OAuth

from ..config import config

oauth = OAuth(config)
