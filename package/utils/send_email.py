from flask import current_app
from time import sleep

from .. import db
from ..models import Otp
from .smt import send

def send_email(email, name, verification_code, _id=None, otp=None):
    attempts = 0
    max_attempts = 3
    retry_delay = 2
    
    current_app.logger.info(f"Sending OTP email to {email}")
    while attempts < max_attempts:
        result = send(
            recipients=[email],
            subject="OTP Code",
            body=f"Hello {name} Your OTP code is: {verification_code}"
        )

        if result is None:
            if _id and otp is None:
                new_otp = Otp(verification_code=verification_code, user_id=_id)
                db.session.add(new_otp)
                return None

            otp.verification_code = verification_code
            return None
        
        current_app.logger.error(f"Email attempt {attempts + 1} failed: {result['msg']}")
        attempts += 1

        if attempts < max_attempts:
            sleep(retry_delay)

    db.session.rollback()
    return result