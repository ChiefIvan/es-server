from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy.exc import SQLAlchemyError

from . import db, limiter
from .models import User, Event

views = Blueprint("views", __name__)

@views.route("/get_privilege", methods=["GET"])
@jwt_required()
def get_privilege():
    current_user_id = get_jwt_identity()

    try:
        user = User.query.filter_by(id=current_user_id).first()
        return jsonify({
            "privilege": user.privilege,
        }), 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error creating User: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in sending OTP: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    

@views.route("/retrieve_users", methods=["GET"])
@jwt_required()
def retrieve_users():
    try:
        users = db.session.query(User).filter(User.privilege != 3, User.is_verified == True).all()
        user_list = [
            {
                "id": user.id,
                "email": user.email,
                "username": f"{user.fname} {user.lname}",
                "privilege": {
                    "3": "Super Admin",
                    "2": "Admin",
                    "1": "User",
                    "0": "Guest"
                }.get(str(user.privilege), "Guest"),
                "faculty": user.faculty,
                "program": user.program,
                "_id": user._id
            } for user in users
        ]

        return jsonify(user_list), 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error retrieving users: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in retrieving users: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    
@views.route("/retrieve_faculty_based_users", methods=["GET"])
@jwt_required()
def retrieve_faculty_based_users():
    current_user = get_jwt_identity()

    try:
        user = User.query.filter_by(id=current_user).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404

        users = db.session.query(User).filter(User.privilege == 1, User.program == user.program, User.faculty == user.faculty).all()
        user_list = [
            {
                "id": user.id,
                "email": user.email,
                "username": f"{user.fname} {user.lname}",
                "privilege": {
                    "3": "Super Admin",
                    "2": "Admin",
                    "1": "User",
                    "0": "Guest"
                }.get(str(user.privilege), "Guest"),
                "faculty": user.faculty,
                "program": user.program,
                "_id": user._id
            } for user in users
        ]

        return jsonify(user_list), 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error retrieving users: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in retrieving users: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    

@limiter.limit("3 per minute")
@views.route("/change_privilege", methods=["POST"])
@jwt_required()
def change_privilege():
    client_data = request.get_json(silent=True)

    try:
        if not client_data or "_id" not in client_data or "privilege" not in client_data:
            return jsonify({"msg": "Invalid request data"}), 400

        user = User.query.filter_by(_id=client_data["_id"]).first()

        user.privilege = client_data["privilege"]
        db.session.commit()
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error changing user privilege: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in changing user privilege: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500

    return jsonify({}), 200

@views.route("/create_event", methods=["POST"])
@jwt_required()
def create_event():
    client_data = request.get_json(silent=True)

    try:
        if not client_data or "title" not in client_data or "description" not in client_data:
            return jsonify({"msg": "Invalid request data"}), 400

        current_user = get_jwt_identity()
        user = User.query.filter_by(id=current_user).first()

        event = Event(
            title=client_data["title"],
            faculty=user.faculty,
            program=user.program,
            description=client_data["description"],
            start_date=client_data.get("start_date"),
            end_date=client_data.get("end_date"),
            start_time=client_data.get("start_time"),
            end_time=client_data.get("end_time"),
            user_id=current_user
        )

        db.session.add(event)
        db.session.commit()

        return jsonify({"msg": "Event created successfully"}), 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Error creating event: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except Exception as err:
        current_app.logger.error(f"Unexpected error in creating event: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    
@views.route("/retrieve_events", methods=["GET"])
@jwt_required()
def retrieve_events():
    current_user = get_jwt_identity()

    try:
        user = User.query.filter_by(id=current_user).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404

        events = db.session.query(Event).filter(Event.program == user.program, Event.faculty == user.faculty).all()

        events_data = [{
            "id": event.id,
            "title": event.title,
            "description": event.description,
            "start_date": event.start_date.isoformat() if event.start_date else None,
            "end_date": event.end_date.isoformat() if event.end_date else None,
            "start_time": event.start_time.isoformat() if event.start_time else None,
            "end_time": event.end_time.isoformat() if event.end_time else None,
            "user_id": event.user_id
        } for event in events]

        return jsonify({"events": events_data}), 200
    except SQLAlchemyError as err:
        current_app.logger.error(f"Database error while retrieving events: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500
    except AttributeError as err:
        current_app.logger.error(f"Invalid user data: {err}")
        return jsonify({"msg": "Invalid user data"}), 400
    except Exception as err:
        current_app.logger.error(f"Unexpected error while retrieving events: {err}")
        return jsonify({"msg": "Server error, please try again later!"}), 500 
          
