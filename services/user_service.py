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

def create_user(db_id:str, username:str, password:str, auth_level:int, email:str=None): #creates a new user in the specified database
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
    
        hashed_password = generate_password_hash(password)
        new_user = UserModel(
            user_id=generate_user_id(),
            username=username if username else None,
            email=email if email else None,
            password_hash=hashed_password,
            auth_level=auth_level,
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
        if not user:
            return None
        return [user, app] if full_info else user

def update_user(db_id, identifier, username=None, email=None, password=None, time_extension=None, curr=False, revoke=False): #updates a user in the specified database
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        user = UserModel.query.filter_by(user_id=identifier).first()
        try:
            if not user:
                abort(404, description="User not found")
            if username:
                user.username = username
            if email:
                user.email = email
            if password:
                user.password_hash = generate_password_hash(password)
            if time_extension is not None and not revoke:
                if not user.auth_token_expiration or user.auth_token_expiration < datetime.now() or curr:
                    if time_extension <= 0:
                        abort(400, description="Time extension must be greater than 0 to create/refresh a valid token.")
                    user.auth_token_expiration = datetime.now() + timedelta(minutes=time_extension)
                else:
                    user.auth_token_expiration = user.auth_token_expiration + timedelta(minutes=time_extension)
                user.auth_token = generate_auth_token()
            elif revoke:
                user.auth_token = None
                user.auth_token_expiration = datetime.now()
            db.session.commit()
            print(user) #required to avoid lazy loading issues (detached instance)
        except Exception as e:
            db.session.rollback()
            print(e)
            abort(500)
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

def validate_auth_token(db_id, token): #checks if the user has a valid auth token
    load_dotenv()
    testing = os.getenv("TESTING")
    if testing == "True":
        return True
    if not token or not db_id:
        return False
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        user = UserModel.query.filter_by(auth_token=token).where(UserModel.auth_token_expiration > datetime.now()).first()
        if not user:
            return False
        return True

def validate_actions(location:str, db_id:str, user_id:str, use_hierarchy:bool=False, act_on:str=None): #validates if the provided token allows actions at the specified location
    registry = RegistryModel.query.filter_by(db_id=db_id).first().user_auth_scheme
    registry = json.loads(registry)
    db, app = connect_with_user_db(db_id)
    with app.app_context():
        user = UserModel.query.filter_by(user_id=user_id).first()
        if not user:
            abort(404, description="User not found.")
        user = int(user.auth_level)
    notation = registry["notation"]
    allow_key = registry["allow_key"]
    bigger_than, smaller_than, allow, ban = unpack_settings(allow_key, location, notation, registry["translation_key"] if notation == "string" else None)
    
    action_allowed = False
    if bigger_than is not None and user > bigger_than and str(user) not in ban if ban else True:
        action_allowed = True
    elif smaller_than is not None and user < smaller_than and str(user) not in ban if ban else True:
        action_allowed = True
    elif str(user) in allow if allow else False:
        action_allowed = True
    
    if not action_allowed or not use_hierarchy:
        return action_allowed
    
    with app.app_context():
        act_on_user = UserModel.query.filter_by(user_id=act_on).first()
        if not act_on_user:
            abort(404, description="Target user not found.")
        act_on_level = int(act_on_user.auth_level)
    hierarchy = registry["hierarchy"]
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
        bigger_than, smaller_than, allow, ban = unpack_settings(advanced, location, notation, registry["translation_key"] if notation == "string" else None, handle_self=True, self=user)
        if bigger_than is not None and act_on_level < bigger_than and str(act_on_level) not in ban:
            return True
        elif smaller_than is not None and act_on_level > smaller_than and str(act_on_level) not in ban:
            return True
        elif str(act_on_level) in allow:
            return True
        elif str(user) in exceptions:
            return True
        return False
    
    else:
        abort(500, description="Invalid hierarchy setting for 'main'. Can't be handled.")

def unpack_settings(key, location, notation, translation_key=None, handle_self:bool=False, self:int=None):
    try:
        location_key = key[location]
    except KeyError:
        try:
            location_key = key["else"]
        except KeyError:
            abort(500, description=f"Invalid settings; missing '{location}' and 'else' keys at {key}")
    
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
            if self and "self" in temp_smaller_than:
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