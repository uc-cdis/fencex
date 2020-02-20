from ...config import config

RAS_URI = config("RAS_URI", default="https://sts.nih.gov")
RAS_CLIENT_ID = config("RAS_CLIENT_ID", default="")
RAS_CLIENT_SECRET = config("RAS_CLIENT_SECRET", default="")
