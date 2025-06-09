from flask import Blueprint, jsonify, request, url_for, current_app, render_template, flash, redirect
from flask_jwt_extended import create_access_token, jwt_required, get_jwt

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta 
from random import randint
from time import sleep

from . import db, limiter
from .models import User, Otp, Revoked
from .utils.sanitizer import Sanitize
from .utils.validator import validate_entries, validate_password
from .utils.smt import send
from .utils.send_email import send_email

auth = Blueprint("auth", __name__)


@limiter.limit("5 per minute")
@auth.route("/login", methods=["POST"])
def login():
    client_data = request.get_json(silent=True)

    if not client_data or "_id" not in client_data or "password" not in client_data:
        return jsonify({"msg": "Missing ID or Password!"}), 400  

    is_clean = Sanitize(client_data, allowed_fields=["_id", "password"]).clean()
    if is_clean is not None:
        return jsonify(is_clean), 400

    try:
        user = User.query.filter_by(_id=client_data["_id"]).first()

        if not user:
            return jsonify({"msg": "Invalid credentials!"}), 401    

        if not user.is_verified:
            return jsonify({"msg": "Please verify your account first!"}), 403
        
        if hasattr(user, "failed_attempts") and hasattr(user, "locked_until"):
            if user.locked_until and user.locked_until > datetime.utcnow():
                remaining_time = (user.locked_until - datetime.utcnow()).seconds // 60
                return jsonify({"msg": f"Account locked! Try again in {remaining_time} minutes"}), 403

        if not check_password_hash(user.password, client_data["password"]):
            if hasattr(user, "failed_attempts"):
                user.failed_attempts = (user.failed_attempts or 0) + 1

                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    current_app.logger.info(f"Account {user.email} locked due to excessive failed attempts")

                db.session.commit()

            sleep(0.5)
            return jsonify({"msg": "Invalid credentials!"}), 401
        
        if hasattr(user, "failed_attempts") and user.failed_attempts:
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

        access_token = create_access_token(identity=str(user.id))
        current_app.logger.info(f"User {user.email} logged in successfully")

        response = jsonify({
                "msg": "Login Successful",
                "token": access_token
            })
        
        return response, 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Database error in login: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in login: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    

@limiter.limit("5 per minute")
@auth.route("/signup", methods=["POST"])
def signup(): 
    client_data = request.get_json(silent=True)

    if not client_data:
        current_app.logger.error(f"Invalid or missing data!")
        return jsonify({"msg": "Invalid or missing data!"}), 400

    REQUIRED_FIELDS = ["email", "fname", "lname", "password", "password_confirm", "_id", "faculty", "program"]

    if not all(field in client_data for field in REQUIRED_FIELDS):
        print(client_data)
        current_app.logger.error(f"Missing required fields!")
        return jsonify({"msg": "Missing required fields!"}), 400

    is_clean = Sanitize(client_data, allowed_fields=REQUIRED_FIELDS).clean()
    if is_clean is not None:
        current_app.logger.error(f"Sanitization error: {is_clean}")
        return jsonify(is_clean), 400

    is_valid = validate_entries(client_data, allowed_fields=REQUIRED_FIELDS)
    if is_valid is not None:
        current_app.logger.error(f"Validation error: {is_clean}")
        return jsonify(is_valid), 400

    try: 
        user = User.query.filter_by(email=client_data["email"], _id=client_data["_id"]).first()
        
        if user:
            current_app.logger.error(f"User already exists!")
            return jsonify(
                {"msg": "Email already exist!, please try another one."}
            ), 409
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error checking existing user: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500

    try:
        new_user = User(
            email=client_data["email"],
            fname=client_data["fname"],
            lname=client_data["lname"],
            _id=client_data["_id"],
            privilege=0,
            faculty=client_data.get("faculty"),
            program=client_data.get("program"),
            is_verified=False,
            password=generate_password_hash(client_data["password"], method="pbkdf2:sha256")
        )

        db.session.add(new_user)
        db.session.flush()

        verification_code = str(randint(100000, 999999))
        
        email_result = send_email(client_data["email"], client_data["fname"], verification_code, _id=new_user.id)
        if isinstance(email_result, dict):
            db.session.rollback()
            return jsonify(email_result), 500

        db.session.commit()
        return jsonify({}), 200
    except SQLAlchemyError as err:
        db.session.rollback()
        current_app.logger.error(f"Error creating User: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error in sending OTP: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500


@limiter.limit("1 per minute")
@auth.route("/resend_otp", methods=["POST"])
def resend_otp():
    client_data = request.get_json(silent=True)

    if not client_data:
        return jsonify({"msg": "Invalid or missing data!"}), 400

    if "email" not in client_data:
        return jsonify({"msg": "Missing required fields!"}), 400

    is_clean = Sanitize(client_data, allowed_fields=["email"]).clean()
    if is_clean is not None:
        return jsonify(is_clean), 400

    try:
        user = User.query.filter_by(email=client_data["email"]).first()
        if not user:
            return jsonify({"msg": "User not found!"}), 404
        
        otp = Otp.query.filter_by(user_id=user.id).first()
        if not otp:
            return jsonify({"msg": "No OTP found for this user!"}), 404
        
        verification_code = str(randint(100000, 999999))
        
        email_result = send_email(client_data["email"], user.fname, verification_code, otp=otp)

        if isinstance(email_result, dict):
            db.session.rollback()
            return jsonify(email_result), 500

        db.session.commit()
        return jsonify({}), 200 
    except SQLAlchemyError as err:
        db.session.rollback()
        current_app.logger.error(f"Database error in resend OTP: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error in resend OTP: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500


@limiter.limit("5 per minute")
@auth.route("/verify_otp", methods=["POST"])
def verify():
    client_data = request.get_json(silent=True)

    print(client_data)

    if not client_data:
        return jsonify({"msg": "Invalid or missing data!"}), 400

    if "verification_code" not in client_data or "email" not in client_data:
        return jsonify({"msg": "Missing required fields!"}), 400

    is_clean = Sanitize(client_data, allowed_fields=["verification_code", "email"]).clean()
    if is_clean is not None:
        return jsonify(is_clean), 400

    try:
        user = User.query.filter_by(email=client_data["email"]).first()
        if not user:
            return jsonify({"msg": "User not found!"}), 404
        
        otp = Otp.query.filter_by(user_id=user.id).first()
        if not otp:
            return jsonify({"msg": "Invalid OTP!"}), 400
        
        if otp.verification_code != client_data["verification_code"]:
            return jsonify({"msg": "Invalid OTP!"}), 400
        
        db.session.delete(otp)
        user.is_verified = True
        db.session.commit()

        current_app.logger.info(f"User {user.email} verified successfully")
        
        return jsonify({}), 200
    except SQLAlchemyError as err:
        db.session.rollback()
        current_app.logger.error(f"Database error in verification: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error in verification: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500


@limiter.limit("5 per minute")
@auth.route("/forgot_password", methods=["POST"])
def forgot_password():
    client_data = request.get_json(silent=True)

    if not client_data:
        return jsonify({"msg": "Invalid or missing data!"}), 400

    if "email" not in client_data:
        return jsonify({"msg": "Missing required fields!"}), 400

    is_clean = Sanitize(client_data, allowed_fields=["email"]).clean()
    if is_clean is not None:
        return jsonify(is_clean), 400

    try:
        user = User.query.filter_by(email=client_data["email"]).first()
        if not user:
            return jsonify({"msg": "User not found!"}), 404
        
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        token = serializer.dumps(user.email, salt=current_app.config["SECURITY_PASSWORD_SALT"])

        url = url_for(
            "auth.reset_password",
            token=token,
            _external=True
        )

        result = send(
            recipients=[user.email],
            subject="Password Reset Request",
            body=f"Hello {user.fname},\n\nTo reset your password, click the link below:\n{url}\n\nIf you did not request this, please ignore this email."
        )

        if result is not None:
            return jsonify(result), 400

        return jsonify({})
    except SQLAlchemyError as err:
        db.session.rollback()
        current_app.logger.error(f"Database error in forgot password: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error in forgot password: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    

@auth.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        query = Revoked(jti=jti, revoked_at=datetime.now())

        db.session.add(query)
        db.session.commit()

        sleep(5)
        return jsonify({})
    except SQLAlchemyError as err:
        current_app.logger.error(f"Database error in forgot password: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in logout: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    

@auth.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    def render_message(title, message, color, status=200):
            return render_template("message.html", 
                                content={"title": title, 
                                        "content": message, 
                                        "color": color}), status

    serializer = URLSafeTimedSerializer(current_app.config.get("SECRET_KEY"))

    try:
        email = serializer.loads(token, salt=current_app.config.get("SECURITY_PASSWORD_SALT"), max_age=3600)
    except SignatureExpired as err:
        return render_message(
            "EventSync | Reset Password",
            "The confirmation link has expired!",
            "red",
            400
        )
    except BadSignature as err:
        return render_message(
            "EventSync | Reset Password",
            "Invalid confirmation link!",
            "red",
            400
        )
    except Exception as err:
        current_app.logger.error(f"Error in Reset Password: {err}")
        return render_message(
            "EventSync | Error",
            "Something went wrong!",
            "red",
            500
            ),
    
    if request.method == "POST":
        new_password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")

        if not new_password or not password_confirm:
            flash({"error": "Invalid Credentials!"}, category="error") 
            return redirect(url_for("auth.reset_password", token=token))

        is_password_string_valid = validate_password(new_password, password_confirm)
        if is_password_string_valid is not None:
            flash({"error": is_password_string_valid.get("msg")}, category="error")
            return redirect(url_for("auth.reset_password", token=token))

        try:
            user = User.query.filter_by(email=email).first()

            if user.last_password_reset_request and \
                user.last_password_reset_request > datetime.utcnow() - timedelta(days=7):
                return render_message(
                    "EventSync | Reset Password",
                    "You can only change your password once every 7 days! ❌",
                    "red",
                    400
                )

            if not user:
                return render_message(
                    "EventSync | Reset Password",
                    "User not found!",
                    "red",
                    404
                )

            if check_password_hash(user.password, new_password):
                flash(
                    {"error":  "Your new password must be different from your old one!"}, category="error")
                return redirect(url_for("auth.reset_password", token=token))
            
            user.password = generate_password_hash(
                new_password, method="pbkdf2:sha256")
            user.last_password_reset_request = datetime.utcnow()
            db.session.commit()
            
            return render_message(
                "EventSync | Reset Password",
                "Password changed Succesfully ✅",
                "green",
                200
            ),

            
        except SQLAlchemyError as err:
            current_app.logger.error(f"Database error in Forgot Password: {err}")
            return render_message(
                "EventSync | Error",
                "Something went wrong!",
                "red",
                500
            )

    return render_template("reset.html")
    


