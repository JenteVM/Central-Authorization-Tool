"""
module `user_resource` defines the Flask-RESTful resources for handling user-related API endpoints.

Resources:
- `UserListResource`: a resource for handling requests to the `/api/registry/<db_id>/users` endpoint, allowing retrieval of all users and creation of new users.
- `UserLookupResource`: a resource for handling requests to the `/api/registry/<db_id>/users/<id_method>/<identifier>` endpoint, allowing retrieval, updating and deletion of specific users by their unique identifier (`user_id`, `username` or `email`).
- `UserAuthenticateResource`: a resource for handling requests to the `/api/registry/<db_id>/authenticate` endpoint, allowing users to create, extend, refresh or revoke their auth token.
"""
from flask_restful import Resource, reqparse, fields, marshal_with
from flask import abort
import html
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
    """
    class `UserListResource` is a Flask-RESTful resource for handling requests to the `/api/registry/<db_id>/users` endpoint, allowing retrieval of all users and creation of new users.

    functions:
    - `get`: handles GET requests to retrieve a list of all users. It checks for the appropriate authorization and permissions before returning the list of users.
    - `post`: handles POST requests to create a new registry entry. Returns the details of the newly created registry entry and user.
    """
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self, db_id):
        """function `get` handles GET requests to retrieve a list of all users. It checks for the appropriate authorization and permissions before returning the list of users."""
        if not check_get_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired token.")
        if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_get_all", fallback_location="user_get", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, bypassable=True):
            abort(403, description="Insufficient permissions.")
        return get_all_users(html.escape(db_id) if db_id else None), 200
    
    @marshal_with(user_creation_fields)
    @limiter.limit("2 per second;10 per minute")
    def post(self, db_id):
        """
        function `post` handles POST requests to create a new registry entry. Returns the details of the newly created registry entry and user.

        required arguments:
        - `app_name`: the name of the application, *has to be provided in the request body.*
        - `username`: the users username, *has to be provided in the request body.*
        - `password`: the users password, *has to be provided in the request body.*

        optional arguments:
        - `email`: the email address for the user associated with the new registry entry, *has to be provided in the request body.*

        auth requirements:
        - `origin`: the request must come from an `allowed_origin` specified in the environment variable `ALLOWED_REGISTRY_CREATORS`. Returns `http 403` if the origin is not authorized.
        - `auth_token`: the request must include a valid `auth_token` *which has to be provided in the headers as `X-Auth-Token`*. It has to have sufficient permissions to create a registry entry.

        returns:
        - a `dict`: it contains the details of the newly created user, along with `http 201`.
        """
        if not check_post_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired token.")
        args = user_args.parse_args()
        if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_post_new", fallback_location="user_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=args["auth_level"], act_on_is_int=True):
            abort(403, description="Insufficient permissions.")
        new_user = create_user(
            html.escape(db_id),
            username=html.escape(args["username"]) if args["username"] else abort(400, description="username is a required field."),
            email=html.escape(args["email"]) if args["email"] else None,
            password=html.escape(args["password"]) if args["password"] else abort(400, description="password is a required field."),
            auth_level=html.escape(args["auth_level"]),
        )
        return new_user, 201

class UserLookupResource(Resource): #queries a singular user instance
    """
    class `UserLookupResource` is a Flask-RESTful resource for handling requests to the `/api/registry/<db_id>/users/<id_method>/<identifier>` endpoint, allowing retrieval, updating and deletion of specific users.

    functions:
    - `get`: handles GET requests to retrieve a specific user's details. It checks for the appropriate authorization and permissions, validates the input data, retrieves the specified user's details, and returns them.
    - `patch`: handles PATCH requests to update a specific user's details. Returns the updated user details.
    - `delete`: handles DELETE requests to delete a specific user. It checks for the appropriate authorization and permissions, validates the input data, deletes the specified user, and returns a success message.
    """
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self, db_id, id_method, identifier):
        """function `get` handles GET requests to retrieve a specific user's details. It checks for the appropriate authorization and permissions, validates the input data, retrieves the specified user's details, and returns them."""
        if not check_get_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired token.")
        if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_get_one", fallback_location="user_get", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, bypassable=True):
            abort(403, description="Insufficient permissions.")
        user = get_user_by(html.escape(db_id) if db_id else None, id_method, identifier)
        if user is not None:
            return user
        abort(404, description="User not found.")
    
    @marshal_with(user_limited_fields)
    @limiter.limit("2 per second;10 per minute")
    def patch(self, db_id, id_method, identifier):
        """
        function `patch` handles PATCH requests to update a specific user's details. Returns the updated user details.

        required arguments:
        - `id_method`: the method to identify the user to update, *has to be provided in the URL path.*
        - `identifier`: the value corresponding to the `id_method` to identify the user , *has to be provided in the URL path.*

        optional arguments:
        - `username`: the new username for the user, *has to be provided in the request body.*
        - `email`: the new email address for the user, *has to be provided in the request body.*
        - `password`: the new password for the user, *has to be provided in the request body.*
        - `auth_level`: the new auth level for the user, *has to be provided in the request body.*

        auth requirements:
        - `origin`: the request must come from an `allowed_origin` specified in the db linked to `db_id`. *`db_id` has to be provided in the URL*. Returns `http 403` if the origin is not authorized.
        - `auth_token`: the request must include a valid `auth_token` *which has to be provided in the headers as `X-Auth-Token`*. It has to have sufficient permissions to perform the specified updates on the user.

        returns:
        - a `dict`: it contains the updated details of the user, along with `http 200`.
        """
        if not check_post_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired token.")
        args = user_args.parse_args()
        user = get_user_by(html.escape(db_id) if db_id else None, id_method, identifier)
        if user is None:
            abort(404, description="User not found.")
        if args["username"]:
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_patch_username", fallback_location="user_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=user.user_id, user_is_act_on=True):
                abort(403, description="Insufficient permissions.")
        if args["email"]:
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_patch_email", fallback_location="user_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=user.user_id, user_is_act_on=True):
                abort(403, description="Insufficient permissions.")
        if args["password"]:
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_patch_password", fallback_location="user_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=user.user_id, user_is_act_on=True):
                abort(403, description="Insufficient permissions.")
        if args["auth_level"]:
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_patch_auth_level", fallback_location="user_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=args["auth_level"], act_on_is_int=True):
                abort(403, description="Insufficient permissions.")
        updated_user = update_user(
            html.escape(db_id) if db_id else None,
            user.user_id,
            username=html.escape(args["username"]) if args["username"] else None,
            email=html.escape(args["email"]) if args["email"] else None,
            password=html.escape(args["password"]) if args["password"] else None,
            auth_level=html.escape(args["auth_level"]) if args["auth_level"] else None,
        )
        return updated_user, 200

    @marshal_with({"message": fields.String})
    @limiter.limit("2 per second;10 per minute")
    def delete(self, db_id, id_method, identifier):
        """function `delete` handles DELETE requests to delete a specific user. It checks for the appropriate authorization and permissions, validates the input data, deletes the specified user, and returns a success message."""
        if not check_post_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired token.")
        user = get_user_by(html.escape(db_id) if db_id else None, html.escape(id_method) if id_method else None, html.escape(identifier) if identifier else None)
        if user is None:
            abort(404, description="User not found.")
        else:
            user = user.user_id
        if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_delete", fallback_location="user_delete", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, use_hierarchy=True, act_on=user):
            abort(403, description="Insufficient permissions.")
        success = delete_user(html.escape(db_id) if db_id else None, html.escape(id_method) if id_method else None, html.escape(identifier) if identifier else None)
        return success, 200

class UserAuthenticateResource(Resource): #authenticates a user against the database
    """class `UserAuthenticateResource` is a Flask-RESTful resource for handling requests to the `/api/registry/<db_id>/authenticate` endpoint, allowing users to create, extend, refresh or revoke their auth token."""
    @marshal_with(auth_token_fields)
    @limiter.limit("2 per second;10 per minute")
    def post(self, db_id, method, time_extension:int):
        """
        function `post` handles POST requests to authenticate a user and manage their authentication token. It checks for the appropriate authorization and permissions, validates the input data, authenticates the user, and returns the user's authentication token details.

        required arguments:
        - `method`: the specific authentication-related action to perform, *has to be provided in the URL path*. It can be one of the following:
        - `time_extension`: the amount of time (in minutes) to extend or refresh the user's authentication token, *has to be provided in the URL path for the methods `extend` and `current`.*

        auth requirements:
        - `origin`: the request must come from an `allowed_origin` specified in the db linked to `db_id`. *`db_id` has to be provided in the URL*. Returns `http 403` if the origin is not authorized.
        - `auth_token`: for methods other than `create` and `login`, the request must include a valid `auth_token` *which has to be provided in the headers as `X-Auth-Token`*. It has to have sufficient permissions to perform the specified authentication-related action.

        returns:
        - a `dict`: it contains the user's authentication token details (user_id, auth_level, auth_token, auth_token_expiration) and `http 200`.
        """
        if not check_post_level_auth(html.escape(db_id) if db_id else None):
            abort(403, description="Unauthorized Origin.")
        args = user_auth_args.parse_args()
        if method == "create" or method == "login":
            id_method = "username"
            identifier = args["username_or_email"]
            user = get_user_by(html.escape(db_id) if db_id else None, html.escape(id_method) if id_method else None, html.escape(identifier) if identifier else None)
            if user is None:
                id_method = "email"
                user = get_user_by(html.escape(db_id) if db_id else None, html.escape(id_method) if id_method else None, html.escape(identifier) if identifier else None)
            if user is not None:    
                if check_password_hash(user.password_hash, args["password"]):
                    authorized_user = update_user(html.escape(db_id) if db_id else None, user.user_id, time_extension=time_extension)
                    return authorized_user
                abort(401, description="Wrong password.")
            else:
                abort(404, description="User not found.")
        else:
            user = get_user_by(db_id, id_method = "auth_token", identifier = html.escape(get_auth_token()) if get_auth_token() else None)
            if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None, bypassable=False):
                return abort(401, description="Invalid or expired token.")
            if method == "extend" or method == "ext":
                if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_post_token_extend", fallback_location="user_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                    abort(403, description="Insufficient permissions.")
                authorized_user = update_user(html.escape(db_id) if db_id else None, user.user_id, time_extension=time_extension)
            elif method == "current" or method == "curr":
                if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_post_token_current", fallback_location="user_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                    abort(403, description="Insufficient permissions.")
                authorized_user = update_user(html.escape(db_id) if db_id else None, user.user_id, time_extension=time_extension, curr=True)
            elif method == "refresh" or method == "ref":
                if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_post_token_refresh", fallback_location="user_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                    abort(403, description="Insufficient permissions.")
                authorized_user = update_user(html.escape(db_id) if db_id else None, user.user_id, refresh=True)
            elif method == "revoke" or method == "rev":
                if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_delete_token", fallback_location="user_delete", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                    abort(403, description="Insufficient permissions.")
                authorized_user = update_user(html.escape(db_id) if db_id else None, user.user_id, revoke=True)
            else:
                abort(400, description="Invalid method.")
            return authorized_user