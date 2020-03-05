from gino import Gino
from sqlalchemy.dialects.postgresql import JSONB, UUID

db = Gino()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(UUID(), primary_key=True)
    profile = db.Column(JSONB(), nullable=False, default={})
    name = db.StringProperty()
    nih_login_id = db.StringProperty()

    def __init__(self, **values):
        super().__init__(**values)
        self._identities = []

    @property
    def identities(self):
        return self._identities

    def add_identity(self, identity):
        self._identities.append(identity)

    def get_user_id(self):
        return self.id


class Identity(db.Model):
    __tablename__ = "identities"

    id = db.Column(db.BigInteger(), primary_key=True)
    sub = db.Column(db.Unicode(), nullable=False)
    idp = db.Column(db.Unicode(), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    profile = db.Column(JSONB(), nullable=False, default={})
    identities_idp_sub_idx = db.Index(
        "identities_idp_sub_idx", "sub", "idp", unique=True
    )
