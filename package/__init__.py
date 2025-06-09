from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from os import getenv
from dotenv import load_dotenv
from datetime import timedelta
from werkzeug.security import generate_password_hash
from sqlalchemy import inspect, event
from sqlalchemy.exc import SQLAlchemyError, NoInspectionAvailable
from logging import Formatter, DEBUG
from logging.handlers import RotatingFileHandler
from click import option


app = Flask(__name__)
db = SQLAlchemy()
mail = Mail()
jwt = JWTManager()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

handler = RotatingFileHandler("server_logs.log", maxBytes=1000000, backupCount=5)
handler.setFormatter(
    Formatter(
        "%(levelname)s (%(asctime)s): %(message)s (Line: %(lineno)d [%(filename)s])",
        datefmt="%d/%m/%Y %I:%M:%S %p"
    )
)

app.logger.addHandler(handler)
app.logger.setLevel(DEBUG)

load_dotenv()

app.config["SECRET_KEY"] = getenv("SK")
app.config["DEBUG"] = False
app.config["JWT_SECRET_KEY"] = getenv("SK")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["SECURITY_PASSWORD_SALT"] = getenv("SALT")
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{getenv('DB')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_DEFAULT_SENDER"] = getenv("EMAIL")
app.config["MAIL_USERNAME"] = getenv("EMAIL")
app.config["MAIL_PASSWORD"] = getenv("PASS")

db.init_app(app)
mail.init_app(app)
jwt.init_app(app)
limiter.init_app(app)

from .models import User, Revoked
from .views import views
from .auth import auth

app.register_blueprint(auth, url_prefix="/auth")
app.register_blueprint(views, url_prefix="/views")


def tables_exist():
    required_tables = ["user", "revoked"]
    
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        return all(table in tables for table in required_tables)
    except NoInspectionAvailable as err:
        app.logger.error(f"Error at Inspector: {err}")
        return False
    

def create_admin():
    admin_email = getenv("ADMIN_EMAIL")
    admin_pass = getenv("ADMIN_PASS")

    if not admin_email and not admin_pass:
        app.logger.error("Error: ADMIN_EMAIL or ADMIN_PASS is not set")
        return

    with app.app_context():
        try:
            admin = User.query.filter_by(email=admin_email).first()

            if admin:
                app.logger.info(f"Admin {admin_email} already exists")
                return 

            add_admin = User(
                email=admin_email,
                fname="Admin",
                lname="",
                privilege="3",
                faculty="N/A",
                program="N/A",
                is_verified=True,
                _id="0000-0000",
                password=generate_password_hash(
                    admin_pass, method="pbkdf2:sha256")
            )

            db.session.add(add_admin)
            app.logger.info(f"Admin {admin_email} created successfully")
        except SQLAlchemyError as err:
            app.logger.error(f"Error at Creating Admin: {err}")
            db.session.rollback()
        else:
            db.session.commit()


@jwt.user_identity_loader
def user_loader(id):
    return id


@jwt.user_lookup_loader
def user_lookup_callback(jwt_header, decoded_token):
    id = decoded_token["sub"]
    return User.query.get(int(id))


@jwt.token_in_blocklist_loader
def revoked_tokens(jwt_header, decoded_token):
    jti = decoded_token['jti']
    
    try:
        revoked_token = Revoked.query.filter_by(jti=jti).scalar()
        return revoked_token is not None
    except SQLAlchemyError as err:
        app.logger.error(f"Error retrieving revoked token: {err}")
        return False
    
@app.errorhandler(429)
def handle_rate_limit_exceeded(e):
    return jsonify({"msg": "Too many login attempts! Please wait a minute and try again."}), 429


@app.cli.command("db-init")
def db_init():
    with app.app_context():
        is_exist = tables_exist()

        if is_exist:
            print("db already exists!")
            return

        try:
            db.create_all()
            create_admin()
        except SQLAlchemyError as err:
            app.logger.error(f"Error Creating Schema: {err}")
            print("Error Creating Schema!")


@app.cli.command("db-drop")
@option('--drop-schema', default=False, is_flag=True, help='Drop the entire schema/database')
def db_drop(drop_schema):
    with app.app_context():
        try:
            db.drop_all()
            if drop_schema:
                db.session.execute(db.text("DROP DATABASE IF EXISTS trackdb"))
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error dropping database: {e}")
            raise