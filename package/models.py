from . import db
from sqlalchemy import func


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    _id = db.Column(db.String(50), nullable=False)
    privilege = db.Column(db.Integer, nullable=False, default=0)
    faculty = db.Column(db.String(50))
    program = db.Column(db.String(50))
    is_verified = db.Column(db.Boolean, default=False)
    last_password_reset_request = db.Column(db.DateTime(timezone=True))
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    otp = db.relationship("Otp")


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    faculty = db.Column(db.String(50))
    program = db.Column(db.String(50))
    start_date = db.Column(db.DateTime(timezone=True), nullable=False)
    end_date = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    start_time = db.Column(db.Time(timezone=True), nullable=False)
    end_time = db.Column(db.Time(timezone=True))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    

class Revoked(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(300), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=False)


class Otp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verification_code = db.Column(db.String(6), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
