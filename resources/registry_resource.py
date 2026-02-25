from flask_restful import Resource, reqparse, fields, marshal_with
from services.registry_service import create_registry_entry, get_registry_entry_by_id, get_registry_entries, get_allowed_origins, patch_registry_entry, check_post_level_auth, check_get_level_auth, get_reg_token, get_db_id
from services.user_service import create_user, validate_actions, validate_auth_token, get_user_by, get_auth_token
from utils.db_utils import generate_AO_addition_token, limiter, connect_with_user_db
from flask import app, request, abort
import html

registry_args = reqparse.RequestParser()
registry_args.add_argument("app_name", type=str, required=True, help="App name is required.")
registry_args.add_argument("username", type=str, required=True, help="Username is required.")
registry_args.add_argument("email", type=str)
registry_args.add_argument("password", type=str, required=True, help="Password is required.")

registry_patch_args = reqparse.RequestParser()
registry_patch_args.add_argument("app_name", type=str)
registry_patch_args.add_argument("user_auth_scheme", type=str)
registry_patch_args.add_argument("translation", type=str)
registry_patch_args.add_argument("authorized", type=bool)

registry_creation_fields = {
    "registry": fields.Nested({
        "db_id": fields.String,
        "app_name": fields.String,
        "allowed_origins": fields.String,
        "user_auth_scheme": fields.Raw,
        "AO_addition_token": fields.String,
        "authorized": fields.Boolean,
    }),

    "user": fields.Nested({
        "user_id": fields.String,
        "username": fields.String,
        "email": fields.String,
        "auth_level": fields.String,
        "creation_date": fields.DateTime,
        "message": fields.String,
    }),
}
registry_limited_fields = {
    "db_id": fields.String,
    "app_name": fields.String,
    "user_auth_scheme": fields.Raw,
    "authorized": fields.Boolean,
}
AO_addition_token_fields = {
    "AO_addition_token": fields.String,
    "message": fields.String,
}

class RegistryListResource(Resource): #queries all registry entries and allows creation of new entries
    @marshal_with(registry_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self):
        if not check_get_level_auth(html.escape(get_db_id()) if get_db_id() else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(get_db_id()) if get_db_id() else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired auth token.")
        if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_get_all", fallback_location="registry_get", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, bypassable=True):
            abort(403, description="Insufficient permissions.")
        return get_registry_entries(load_for_return=True)

    @marshal_with(registry_creation_fields)
    @limiter.limit("2 per second;10 per minute")
    def post(self):
        ALLOWED_REGISTRY_CREATORS = get_allowed_origins(partial=True)
        origin = request.headers.get("Origin")
        if origin not in ALLOWED_REGISTRY_CREATORS:
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(get_db_id()) if get_db_id() else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired auth token.")
        if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_post_entry", fallback_location="registry_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
            abort(403, description="Insufficient permissions.")
        args = registry_args.parse_args()
        app_name = html.escape(args["app_name"])
        new_entry = create_registry_entry(app_name)
        print(new_entry)
        new_user = create_user(
            new_entry.db_id if new_entry else abort(500, description="Failed to create registry entry."),
            username=html.escape(args["username"]),
            email=html.escape(args["email"]) if args["email"] else None,
            password=html.escape(args["password"]),
        )
        print(new_user)
        return {"registry": new_entry, "user": new_user}, 201

class RegistryLookupResource(Resource): #queries a singular registry instance
    @marshal_with(registry_limited_fields)
    @limiter.limit("2 per second;60 per minute")
    def get(self, db_id):
        if not check_get_level_auth(html.escape(get_db_id()) if get_db_id() else None):
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(get_db_id()) if get_db_id() else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired auth token.")
        if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_get_one", fallback_location="registry_get", auth_token=html.escape(get_auth_token()) if get_auth_token() else None, bypassable=True):
            abort(403, description="Insufficient permissions.")
        entry = get_registry_entry_by_id(db_id, load_for_return=True)
        if entry:
            return entry, 200
        abort(404, description="Database not found.")

    @marshal_with(registry_limited_fields)
    def patch(self, db_id):
        ALLOWED_REGISTRY_CREATORS = get_allowed_origins(partial=True)
        origin = request.headers.get("Origin")
        if origin not in ALLOWED_REGISTRY_CREATORS:
            abort(403, description="Unauthorized Origin.")
        if not validate_auth_token(html.escape(get_db_id()) if get_db_id() else None, html.escape(get_auth_token()) if get_auth_token() else None):
            return abort(401, description="Invalid or expired auth token.")
        args = registry_patch_args.parse_args()
        if args["app_name"]:
            if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_patch_app_name", fallback_location="registry_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                abort(403, description="Insufficient permissions.")
        if html.escape(args["user_auth_scheme"]) or args["translation"]:
            if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_patch_user_auth_scheme", fallback_location="registry_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                abort(403, description="Insufficient permissions.")
        if args["authorized"] is not None:
            if not validate_actions(db_id=html.escape(get_db_id()) if get_db_id() else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_patch_authorized", fallback_location="registry_patch", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                abort(403, description="Insufficient permissions.")
        updated_entry = patch_registry_entry(
            db_id,
            app_name = html.escape(args["app_name"]) if args["app_name"] else None,
            auth_scheme = args["user_auth_scheme"],
            translation = args["translation"],
            authorized = args["authorized"] if isinstance(args["authorized"], bool) else True,
            load_for_return=True,
        )
        return updated_entry, 200

class RegistryAuthenticateResource(Resource): #adds allowed origins to a registry entry if it has a valid token
    @marshal_with(AO_addition_token_fields)
    @limiter.limit("2 per second;10 per minute")
    def get(self, db_id, method):
        entry = get_registry_entry_by_id(html.escape(db_id) if db_id else None)
        if not entry:
            abort(404, description="db instance not found.")
        
        if not entry.allowed_origins:
            entry.allowed_origins = request.headers.get("Origin")
        elif entry.AO_addition_token and entry.AO_addition_token == get_reg_token() and method == "add":
            if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
                return abort(401, description="Invalid or expired auth token.")
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_post_allowed_origin", fallback_location="registry_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                abort(403, description="Insufficient permissions.")
            entry.allowed_origins = entry.allowed_origins + "," + request.headers.get("Origin")
            patch_registry_entry(html.escape(db_id) if db_id else None, AO_addition_token=None, allowed_origins=entry.allowed_origins)
            return {"message": "Allowed origin added successfully."}, 200
        elif method == "create":
            if not check_post_level_auth(html.escape(db_id) if db_id else None):
                abort(403, description="Unauthorized Origin.")
            if not validate_auth_token(html.escape(db_id) if db_id else None, html.escape(get_auth_token()) if get_auth_token() else None):
                return abort(401, description="Invalid or expired auth token.")
            if not validate_actions(db_id=html.escape(db_id) if db_id else None, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_post_allowed_origin_token", fallback_location="registry_post", auth_token=html.escape(get_auth_token()) if get_auth_token() else None):
                abort(403, description="Insufficient permissions.")
            registry = patch_registry_entry(html.escape(db_id) if db_id else None, AO_addition_token=generate_AO_addition_token(), load_for_return=True)
            return registry, 200
        elif entry.AO_addition_token != get_reg_token() or method == "add":
            abort(403, description="Invalid AO addition token.")
        else:
            abort(400, description="Invalid method.")