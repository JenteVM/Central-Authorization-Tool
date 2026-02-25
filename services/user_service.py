import json
import re
import os
from dotenv import load_dotenv
from flask import abort, request
from models.user_model import UserModel
from models.registry_models import RegistryModel
from utils.db_utils import db, connect_with_user_db, generate_user_id, generate_auth_token
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

def create_user(db_id:str, username:str, password:str, email:str=None, auth_level:int=None): #creates a new user in the specified database
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        email_taken=False
        username_taken=False
        if email:
            if UserModel.query.filter_by(email=email).first():
                email_taken=True
        if UserModel.query.filter_by(username=username).first():
            username_taken=True
        
        if username_taken or email_taken:
            abort(400, description=f"{f'Username: {username}' if username_taken else ''}{' and ' if username_taken and email_taken else ''}{f'Email: {email}' if email_taken else ''} taken.")

        load_dotenv()
        hashed_password = generate_password_hash(password)
        new_user = UserModel(
            user_id=generate_user_id(),
            username=username if username else None,
            email=email if email else None,
            password_hash=hashed_password,
            auth_level=auth_level if auth_level is not None else os.getenv("DEFAULT_AUTH_LEVEL"),
            creation_date=datetime.now(),
        )

        db.session.add(new_user)
        db.session.commit()
        print(new_user) #required to avoid lazy loading issues (detached instance)
        return new_user

def get_all_users(db_id:str): #returns all users in the specified database
    db, app = connect_with_user_db(db_id)
    if not db:
        abort(404, description="Database not found.")
    with app.app_context():
        users = UserModel.query.all()
        return users

def get_user_by(db_id:str, id_method:str, identifier:str, full_info:bool=False): #returns a user from a specific database by the specified method and identifier
    db, app = connect_with_user_db(db_id)
    if not db:
        abort(404, description="Database not found.")
    with app.app_context():
        if id_method == "id":
            user = UserModel.query.filter_by(user_id=identifier).first()
        elif id_method == "username":
            user = UserModel.query.filter_by(username=identifier).first()  
        elif id_method == "email":
            user = UserModel.query.filter_by(email=identifier).first()
        elif id_method == "auth_token":
            user = UserModel.query.filter_by(auth_token=identifier).where(UserModel.auth_token_expiration > datetime.now()).first()
        else:
            abort(404, description="Method not found.")
        print(user)
        if not user:
            return None
        return [user, app] if full_info else user

def update_user(db_id, identifier, username=None, email=None, password=None, time_extension=None, curr=False, revoke=False, refresh=False, auth_level=None, forced_scheme=None, omit_softlock_check=False): #updates a user in the specified database
    if auth_level is not None and not omit_softlock_check and softlock_checker(db_id, identifier, auth_level, forced_scheme=forced_scheme):
        abort(401, description="Action would result in no more users with 'User Patch Auth Level (uPatchAL)' or 'Registry Patch Validate Actions (rPatchVA)' permissions.")
    
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        user = UserModel.query.filter_by(user_id=identifier).first()
        if not user:
            abort(404, description="User not found")
        if username:
            user.username = username
        if email:
            user.email = email
        if password:
            user.password_hash = generate_password_hash(password)
        if revoke:
            user.auth_token = None
            user.auth_token_expiration = datetime.now()
        elif refresh:
            user.auth_token = generate_auth_token()
        elif time_extension is not None:
            if not user.auth_token_expiration or user.auth_token_expiration < datetime.now() or curr:
                if time_extension <= 0:
                    abort(400, description="Time extension must be greater than 0 to create/refresh a valid token.")
                user.auth_token_expiration = datetime.now() + timedelta(minutes=time_extension)
            else:
                user.auth_token_expiration = user.auth_token_expiration + timedelta(minutes=time_extension)
            user.auth_token = generate_auth_token()
        if auth_level is not None:
            user.auth_level = auth_level
        db.session.commit()
        print(user) #required to avoid lazy loading issues (detached instance)
        return user
    
def delete_user(db_id, method, value): #deletes a user from the specified database
    user, app = get_user_by(db_id, method, value, full_info=True)
    with app.app_context():
        if not user:
            abort(404, description="User not found.")
        db.session.delete(user)
        db.session.commit()
        return {"message":"User deleted succesfully."}

def get_auth_token(): #retrieves the auth token from a client request
    token = request.headers.get("X-Auth-Token")
    if not token:
        return None
    return token

def validate_auth_token(db_id, token, bypassable=True): #checks if the user has a valid auth token
    load_dotenv()
    testing = os.getenv("TESTING")
    if testing == "True" and bypassable:
        return True
    if not token or not db_id:
        return False
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        user = UserModel.query.filter_by(auth_token=token).where(UserModel.auth_token_expiration > datetime.now()).first()
        if not user:
            return False
        return True

def softlock_checker(db_id, user_id=None, new_auth_level:int=None, forced_scheme=None, users=None): #validates that there is always an administrative user in the database
    if users is None:
        users = get_all_users(db_id)
    patched_user = None
    if user_id:
        patched_user = UserModel.query.filter_by(user_id=user_id).first()
    for user in users:
        if user_id and user == patched_user:
            user.auth_level = new_auth_level
        registry_patch_user_auth_scheme = validate_actions(db_id=db_id, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_patch_user_auth_scheme", fallback_location="registry_patch", user=user, forced_scheme=forced_scheme)
        user_patch_auth_level = validate_actions(db_id=db_id, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="user_patch_auth_level", fallback_location="user_patch", user=user, forced_scheme=forced_scheme)
        if registry_patch_user_auth_scheme or user_patch_auth_level:
            return False
    return True

def validate_actions(db_id:str, primary_application:str, fallback_application:str, primary_location:str, fallback_location:str, user_id:str=None, auth_token:str=None, user=None, use_hierarchy:bool=False, act_on:str=None, user_is_act_on=False, act_on_is_int=False, forced_scheme:str=None, bypassable=False): #validates if the provided token allows actions at the specified location
    load_dotenv()
    testing = os.getenv("TESTING")
    if testing == "True" and bypassable:
        return True
    if forced_scheme:
        try:
            registry = json.loads(forced_scheme)
        except json.JSONDecodeError as err:
            abort(400, description=f"Invalid syntax in provided scheme: {err}")
    else:
        registry = RegistryModel.query.filter_by(db_id=db_id).first().user_auth_scheme
        registry = json.loads(registry)
    try:
        application_key = registry[primary_application]
    except KeyError:
        try:
            application_key = registry[fallback_application]
        except KeyError:
            try:
                application_key = registry["else"]
            except KeyError:
                abort(500, description=f"Invalid settings; missing '{primary_application}', {fallback_application} and 'else' keys at {registry}")
    notation = application_key["notation"]
    allow_key = application_key["allow_key"]
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        if user is None:
            if user_id:
                user = UserModel.query.filter_by(user_id=user_id).first()
            elif auth_token:
                user = UserModel.query.filter_by(auth_token=auth_token).where(UserModel.auth_token_expiration > datetime.now()).first()
        if user is None:
            abort(404, description="User not found.")
        translation_key = None
        try:
            user = int(user.auth_level)
        except ValueError:
            if notation == "string":
                translation_key = application_key["translation_key"]
                user = int(translation_key[str(user.auth_level)])
            else:
                abort(400, description="Invalid auth level format for user.")
    bigger_than, smaller_than, allow, ban = unpack_settings(key=allow_key, primary_location=primary_location, fallback_location=fallback_location, notation=notation, translation_key=translation_key)
    action_allowed = False
    if allow and int(user) in allow:
        action_allowed = True
    if not ban or int(user) not in ban:
        if bigger_than is not None and user > bigger_than:
            action_allowed = True
        elif smaller_than is not None and user < smaller_than:
            action_allowed = True
    
    if not action_allowed or not use_hierarchy:
        return action_allowed
    
    if user_is_act_on and act_on_is_int:
        abort(400, description="Invalid settings; 'act_on_is_int' can't be true if 'user_is_act_on' is true.")
    if user_is_act_on and act_on != user_id:
        abort(403, description="Tried to patch another user in a field that allows self-patching only.")
    with app.app_context():
        if act_on_is_int:
            act_on_level = int(act_on)
        else:
            act_on_user = UserModel.query.filter_by(user_id=act_on).first()
            if not act_on_user:
                abort(404, description="Target user not found.")
            try:
                act_on_level = int(act_on_user.auth_level)
            except ValueError:
                if notation == "string":
                    translation_key = registry["translation_key"]
                    act_on_level = int(translation_key[str(act_on_user.auth_level)])
                else:
                    abort(400, description="Invalid auth level format for act on user.")
    hierarchy = application_key["hierarchy"]
    main = hierarchy["main"]
    exceptions = hierarchy["except"]
    
    if main == "bigger_than":
        if user > act_on_level or str(user) in exceptions:
            return True
        return False
    
    elif main == "smaller_than":
        if user < act_on_level or str(user) in exceptions:
            return True
        return False
    
    elif main == "advanced":
        advanced = hierarchy["advanced"]
        bigger_than, smaller_than, allow, ban = unpack_settings(key=advanced, primary_location=primary_location, fallback_location=fallback_location, notation=notation, translation_key=registry["translation_key"] if notation == "string" else None, handle_self=True, self=user)
        if str(user) in exceptions or str(act_on_level) in allow:
            return True
        if not ban or str(act_on_level) not in ban:
            if bigger_than is not None and act_on_level < bigger_than:
                return True
            elif smaller_than is not None and act_on_level > smaller_than:
                return True
        return False
    
    else:
        abort(500, description="Invalid hierarchy setting for 'main'. Can't be handled.")

def unpack_settings(key, primary_location, fallback_location, notation, translation_key=None, handle_self:bool=False, self:int=None):
    try:
        location_key = key[primary_location]
    except KeyError:
        try:
            location_key = key[fallback_location]
        except KeyError:
            try:
                location_key = key["else"]
            except KeyError:
                abort(500, description=f"Invalid settings; missing '{primary_location}', {fallback_location} and 'else' keys at {key}")
    
    if handle_self:
        try:
            location_key = location_key[str(self)]
        except KeyError:
            try:
                location_key = location_key["else"]
            except KeyError:
                abort(500, description=f"Invalid settings; missing '{self}' and 'else' keys at {location_key}")

    if notation == "string":
        temp_bigger_than = location_key["bigger_than"]
        temp_smaller_than = location_key["smaller_than"]
        temp_allow = location_key["allow"] if location_key["allow"] else []
        temp_ban = location_key["ban"] if location_key["ban"] else []
        try:
            bigger_than = int(temp_bigger_than) if temp_bigger_than is not None else None
        except ValueError:
            if self and re.fullmatch(r'self([+-]\d+)*', temp_bigger_than):
                bigger_than = int(eval(temp_bigger_than))
            else:
                bigger_than = int(translation_key[temp_bigger_than]) if temp_bigger_than is not None else None
        try:
            smaller_than = int(temp_smaller_than) if temp_smaller_than is not None else None
        except ValueError:
            if self and re.fullmatch(r'self([+-]\d+)*', temp_smaller_than):
                smaller_than = int(eval(temp_smaller_than))
            else:
                smaller_than = int(translation_key[temp_smaller_than]) if temp_smaller_than is not None else None
        allow = []
        for i in range(len(temp_allow)):
            try:
                allow.append(int(temp_allow[i]))
            except ValueError:
                if self and "self" in temp_allow[i]:
                    allow.append(eval(temp_allow[i]))
                else:
                    allow.append(int(translation_key[temp_allow[i]]))
        ban = []
        for i in range(len(temp_ban)):
            try:
                ban.append(int(temp_ban[i]))
            except ValueError:
                if self and "self" in temp_ban[i]:
                    ban.append(eval(temp_ban[i]))
                else:
                    ban.append(int(translation_key[temp_ban[i]]))

    elif notation == "integer":
        bigger_than = int(eval(location_key["bigger_than"])) if location_key["bigger_than"] else None
        smaller_than = int(eval(location_key["smaller_than"])) if location_key["smaller_than"] else None
        allow = [int(eval(a.strip())) for a in location_key["allow"]] if location_key["allow"] else []
        ban = [int(eval(b.strip())) for b in location_key["ban"]] if location_key["ban"] else []

    else:
        abort(500, description="Invalid notation specified in registry settings.")
    return bigger_than, smaller_than, allow, ban