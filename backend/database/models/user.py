"""Define the SQL classes for Users."""

import bcrypt
from backend.database.core import db
from flask_serialize.flask_serialize import FlaskSerialize
from flask_user import UserMixin
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.types import String, TypeDecorator
from ..core import CrudMixin
from enum import Enum


fs_mixin = FlaskSerialize(db)


# Creating this class as NOCASE collation is not compatible with ordinary
# SQLAlchemy Strings
class CI_String(TypeDecorator):
    """Case-insensitive String subclass definition"""

    impl = String

    def __init__(self, length, **kwargs):
        if kwargs.get("collate"):
            if kwargs["collate"].upper() not in ["BINARY", "NOCASE", "RTRIM"]:
                raise TypeError(
                    "%s is not a valid SQLite collation" % kwargs["collate"]
                )
            self.collation = kwargs.pop("collate").upper()
        super(CI_String, self).__init__(length=length, **kwargs)


@compiles(CI_String, "sqlite")
def compile_ci_string(element, compiler, **kwargs):
    base_visit = compiler.visit_string(element, **kwargs)
    if element.collation:
        return "%s COLLATE %s" % (base_visit, element.collation)
    else:
        return base_visit


class UserRole(str, Enum):
    PUBLIC = "Public"
    PASSPORT = "Passport"
    CONTRIBUTOR = "Contributor"
    ADMIN = "Admin"

    def get_value(self):
        if self == UserRole.PUBLIC:
            return 1
        elif self == UserRole.PASSPORT:
            return 2
        elif self == UserRole.CONTRIBUTOR:
            return 3
        else:
            return 4


# Define the User data-model.
class User(db.Model, UserMixin, CrudMixin):
    """The SQL dataclass for an Incident."""

    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(
        "is_active", db.Boolean(), nullable=False, server_default="1"
    )

    # User authentication information. The collation="NOCASE" is required
    # to search case insensitively when USER_IFIND_MODE is "nocase_collation".
    email = db.Column(
        CI_String(255, collate="NOCASE"), nullable=False, unique=True
    )
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default="")

    # User information
    first_name = db.Column(
        CI_String(100, collate="NOCASE"), nullable=False, server_default=""
    )
    last_name = db.Column(
        CI_String(100, collate="NOCASE"), nullable=False, server_default=""
    )

    role = db.Column(db.Enum(UserRole))

    phone_number = db.Column(db.Text)

    # Data Partner Relationships
    partner_association = db.relationship(
        "PartnerMember", back_populates="user", lazy="select")
    member_of = association_proxy("partner_association", "partner")

    def verify_password(self, pw):
        return bcrypt.checkpw(pw.encode("utf8"), self.password.encode("utf8"))

    def get_by_email(email):
        return User.query.filter(User.email == email).first()

    # accept partner invite and join 
    def accept_partner_invitation(self, partner_id, role=MemberRole.SUBSCRIBER):
        partner = db.session.query(Partner).get(partner_id)
        if partner:
            # check if user is already a member of partner
            if not any(member.partner_id == partner_id for member in self.partner_association):
                member = PartnerMember(user=self, partner=partner, role=role)
                db.session.add(member)
                db.session.commit()
                return True
        return False

    # leave partner (or decline invite)
    def leave_partner(self, partner_id):
        partner = db.session.query(Partner).get(partner_id)
        if partner_member:
            db.session.delete(partner_member)
            db.session.commit()
            return True
        return False