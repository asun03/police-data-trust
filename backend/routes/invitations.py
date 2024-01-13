from flask import Blueprint, abort, current_app, request
from flask_jwt_extended import get_jwt
from flask_jwt_extended.view_decorators import jwt_required
from backend.auth.jwt import min_role_required
from backend.database.models.user import User, UserRole

from ..database import db
from ..models.user import User, UserRole
from ..models.invitation import Invitation
from ..schemas import validate, InvitationSchema
from datetime import datetime
from ..database import Partner, PartnerMember, MemberRole, db
from ..schemas import (
    CreatePartnerSchema,
    AddMemberSchema,
    partner_orm_to_json,
    partner_member_orm_to_json,
    partner_member_to_orm,
    partner_to_orm,
    validate,
)

invitation_bp = Blueprint("invitation_routes", __name__, url_prefix="/api/v1/invitations")


@invitation_bp.route("/accept/<int:partner_id>", methods=["POST"])
@jwt_required()
@min_role_required(UserRole.PUBLIC)
@validate()
def accept_partner_invitation(partner_id: int):
    # accept partner invite 
    jwt_decoded = get_jwt()
    current_user = User.get(jwt_decoded["sub"])
    
    invitation = Invitation.query.filter_by(user_id=current_user.id, partner_id=partner_id, is_accepted=False).first()
    partner = Partner.query.get(partner_id)

    if invitation and partner:
        # accept 
        invitation.is_accepted = True
        invitation.date_joined = datetime.now()

        # add partner member 
        partner_member = PartnerMember(user=current_user, partner=partner, role=invitation.role)
        db.session.add(partner_member)
        db.session.commit()

        return {"message": "invite successful."}
    
    return abort(400, "invalid invite or partner")

@invitation_bp.route("/leave/<int:partner_id>", methods=["POST"])
@jwt_required()
@min_role_required(UserRole.PUBLIC)
@validate()
def leave_partner(partner_id: int):
    """leave partner or decline invite."""
    jwt_decoded = get_jwt()
    current_user = User.get(jwt_decoded["sub"])

    partner_member = PartnerMember.query.filter_by(user_id=current_user.id, partner_id=partner_id).first()

    if partner_member:
        # if has a partner, delete it 
        db.session.delete(partner_member)
        db.session.commit()
        return {"message": "left partner"}

    invitation = Invitation.query.filter_by(user_id=current_user.id, partner_id=partner_id, is_accepted=False).first()
    if invitation:
        # decline invitation if it has it 
        db.session.delete(invitation)
        db.session.commit()
        return {"message": "declined invite"}

    return abort(400, "Invalid partner or invite.")


@invitation_bp.route("/", methods=["POST"])
@jwt_required()
@min_role_required(UserRole.PUBLIC)
@validate()
def send_invitation():
    """Send invite to user"""
    jwt_decoded = get_jwt()
    current_user = User.get(jwt_decoded["sub"])

    data = request.context.json
    user_email = data.get("user_email")
    partner_id = data.get("partner_id")
    role = data.get("role", MemberRole.SUBSCRIBER)

    # check if user is already a member of partner
    if not any(member.partner_id == partner_id for member in current_user.partner_association):
        partner = Partner.query.get(partner_id)
        
        if partner:
            # send invite
            invitation = Invitation(user=current_user, partner=partner, role=role)
            db.session.add(invitation)
            db.session.commit()
            return {"message": "Invitation sent successfully."}

    return abort(400, "User is already a member of the partner or invalid partner.")
