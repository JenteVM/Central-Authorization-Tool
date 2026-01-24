from flask_restful import Resource, reqparse, fields, marshal_with
from flask import abort
from services.user_service import get_all_users, get_user_by, create_user, update_user, delete_user, validate_auth_token, validate_actions, get_auth_token
from services.registry_service import check_post_level_auth, check_get_level_auth
from utils.db_utils import limiter
from werkzeug.security import check_password_hash

user_args = reqparse.RequestParser()
user_args.add_argument("username", type=str, required=True, help="Name is required.")
user_args.add_argument("email", type=str)
user_args.add_argument("password", type=str, required=True, help="Password is required.")
user_args.add_argument("auth_level", type=str)

user_auth_args = reqparse.RequestParser()
user_auth_args.add_argument("username_or_email", type=str, default=None)
user_auth_args.add_argument("password", type=str, default=None)

user_creation_fields = {
    "user_id": fields.String,
    "username": fields.String,
    "email": fields.String,
    "auth_level": fields.String,
    "creation_date": fields.DateTime,
    "message": fields.String,
}
user_limited_fields = {
    "user_id": fields.String,
    "username": fields.String,
    "email": fields.String,
    "auth_level": fields.String,
    "creation_date": fields.DateTime,
}
auth_token_fields = {
    "user_id": fields.String,
    "auth_level": fields.String,
    "auth_token": fields.String,
    "auth_token_expiration": fields.DateTime,
}

class UserListResource(Resource): #allows all CRUD operations on all of the users (in that database)
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self, db_id):
        if not check_get_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(db_id, get_auth_token()):
            return abort(403, description="Invalid or expired token.")
        return get_all_users(db_id), 200
    
    @marshal_with(user_creation_fields)
    @limiter.limit("2 per second;10 per minute")
    def post(self, db_id):
        if not check_post_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(db_id, get_auth_token()):
            return abort(403, description="Invalid or expired token.")
        args = user_args.parse_args()
        if not args["auth_level"]:
            abort(400, description="auth_level is a required field.")
        new_user = create_user(
            db_id,
            username=args["username"],
            email=args["email"],
            password=args["password"],
            auth_level=args["auth_level"],
        )
        return new_user, 201

class UserLookupResource(Resource): #queries a singular user instance
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self, db_id, id_method, identifier):
        if not check_get_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(db_id, get_auth_token()):
            return abort(403, description="Invalid or expired token.")
        user = get_user_by(db_id, id_method, identifier)
        if user is not None:
            return user
        abort(404, description="User not found.")
    
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;10 per minute")
    def patch(self, db_id, id_method, identifier):
        if not check_post_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(db_id, get_auth_token()):
            return abort(403, description="Invalid or expired token.")
        args = user_args.parse_args()
        user = get_user_by(db_id, id_method, identifier)
        if user is None:
            abort(404, description="User not found.")
        updated_user = update_user(
            db_id,
            user.user_id,
            username=args["username"],
            email=args["email"],
            password=args["password"],
        )
        return updated_user, 200

    @marshal_with({"message": fields.String})
    @limiter.limit("2 per second;10 per minute")
    def delete(self, db_id, id_method, identifier):
        if not check_post_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(db_id, get_auth_token()):
            return abort(403, description="Invalid or expired token.")
        success = delete_user(db_id, id_method, identifier)
        return success, 200

class UserAuthenticateResource(Resource): #authenticates a user against the database
    @marshal_with(auth_token_fields)
    @limiter.limit("2 per second;10 per minute")
    def post(self, db_id, method, time_extension:int):
        if not check_post_level_auth(db_id):
            abort(403, description="Unauthorized Origin.")
        args = user_auth_args.parse_args()
        if method == "create" or method == "login":
            id_method = "username"
            identifier = args["username_or_email"]
            user = get_user_by(db_id, id_method, identifier)
            if user is None:
                id_method = "email"
                user = get_user_by(db_id, id_method, identifier)
            if user is not None:    
                if check_password_hash(user.password_hash, args["password"]):
                    authorized_user = update_user(db_id, user.user_id, time_extension=time_extension)
                    return authorized_user
                abort(403, description="Invalid credentials.")
            else:
                abort(404, description="User not found.")
        else:
            user = get_user_by(db_id, "auth_token", get_auth_token())
            if not validate_auth_token(db_id, get_auth_token()):
                return abort(403, description="Invalid or expired token.")
            if method == "extend" or method == "ext":
                authorized_user = update_user(db_id, user.user_id, time_extension=time_extension)
            elif method == "current" or method == "curr":
                authorized_user = update_user(db_id, user.user_id, time_extension=time_extension, curr=True)
            elif method == "revoke" or method == "rev":
                authorized_user = update_user(db_id, user.user_id, revoke=True)
            else:
                abort(400, description="Invalid method.")
            return authorized_user