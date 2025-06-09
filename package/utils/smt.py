from flask import current_app
from flask_mail import Message

from sqlalchemy.exc import SQLAlchemyError
from smtplib import SMTPException, SMTPAuthenticationError, SMTPServerDisconnected

from .. import mail

def send(**kwargs):
    try:
        msg = Message(
            **kwargs
        )

        mail.send(msg)
        return None
    except SMTPAuthenticationError as auth_err:
        current_app.logger.error(f"Email authentication failed: {auth_err}")
        return {"msg": "Email server authentication failed, please contact support"}
    except (SMTPServerDisconnected, SMTPException) as smtp_err:
        current_app.logger.error(f"SMTP error sending email: {smtp_err}")
        return {"msg": "Failed to send email due to server issue, please try again later"}
    except SQLAlchemyError as db_err:
        current_app.logger.error(f"Database error during email setup: {db_err}")
        return {"msg": "Server error, please try again later"}
    except Exception as err:
        current_app.logger.error(f"Unexpected error sending email: {err}")
        return {"msg": "Unexpected error, please try again later"}
