"""
module `user_service` defines the functions for handling user-related operations.

functions:
- `create_user`: creates a new user in the specified database with the provided username, password, email, and auth level.
- `get_all_users`: retrieves all users from the specified database.
- `get_user_by`: retrieves a specific user from the specified database based on the provided identifier method and identifier.
- `update_user`: updates a specific user's details in the specified database based on the identifier (user_id) with the provided new details.
- `delete_user`: deletes a specified user (method and value) from a specified database (db_id).
- `get_auth_token`: retrieves the auth token from the request headers.
- `validate_auth_token`: checks if the provided auth token is valid for the specified database.
- `softlock_checker`: checks if a softlock will be created under a given circumstance.
- `validate_actions`: checks if a user has sufficient permissions to perform the specific action they are trying to do. Returns `True` if they do and `False` if not.
- `unpack_settings`: takes a key together with the primary and fallback location keys, notation, and translation key (if needed) to unpack the settings for a specific location in the user authentication scheme defined in the registry entry for the specified database.
"""
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
    """
    function `create_user` creates a new user in the specified database with the provided username, password, email, and auth level.

    required arguments:
    - `db_id`: the database identifier.
    - `username`: a string representing the username for the new user.
    - `password`: a string representing the password for the new user.
    
    optional arguments:
    - `email`: a string representing the email for the new user.
    - `auth_level`: an integer representing the authentication level for the new user.

    returns:
    - a `UserModel` object if the user is successfully created, or an error response if the email or username is already taken in the database.
    """
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
            auth_level=auth_level if auth_level is not None else os.getenv("DEFAULT_USER_AUTH_LEVEL"),
            creation_date=datetime.now(),
        )

        db.session.add(new_user)
        db.session.commit()
        print(new_user) #required to avoid lazy loading issues (detached instance)
        return new_user

def get_all_users(db_id:str): #returns all users in the specified database
    """function `get_all_users` retrieves all users from the specified database. Returns all users as a list of `UserModel` objects."""
    db, app = connect_with_user_db(db_id)
    if not db:
        abort(404, description="Database not found.")
    with app.app_context():
        users = UserModel.query.all()
        return users

def get_user_by(db_id:str, id_method:str, identifier:str, full_info:bool=False): #returns a user from a specific database by the specified method and identifier
    """
    function `get_user_by` retrieves a specific user from the specified database based on the provided identifier method and identifier.

    required arguments:
    - `db_id`: the registry entry to check.
    - `id_method`: the method with which to identify the user. It can be one of the following: "id", "username", "email", or "auth_token".
    - `identifier`: the identifier value to search for based on the provided identifier method.
    
    optional arguments:
    - `full_info`: a `boolean` indicating whether to return the full user object along with the database app context (as a list) or just the user object.
    returns:
    - it returns a `UserModel` object representing the user that matches the provided identifier method and identifier value. If `full_info` is `True`, it returns a list containing the `UserModel` object and the database app context.
    """
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
    """
    function `update_user` updates a specific user's details in the specified database based on the identifier (user_id) with the provided new details.
    
    required arguments:
    - `db_id`: the database identifier.
    - `identifier`: an user_id identifying the user to update.

    optional arguments:
    - `username`: new username for the user.
    - `email`: new email for the user.
    - `password`: new password for the user.
    - `time_extension`: an integer representing the amount of time (in minutes) to extend the user's auth token expiration time by. This is not applicable if `curr` is `True`.
    - `curr`: a boolean indicating whether to extend the user's auth token expiration time from the current time (`True`) or from the existing expiration time (`False`). This is only applicable if `time_extension` is provided.
    - `revoke`: a boolean indicating whether to revoke the user's auth token by setting it to `None` and setting the auth token expiration time to the current time.
    - `refresh`: a boolean indicating whether to refresh the user's auth token by generating a new auth token and setting it without changing the expiration time.
    - `auth_level`: an integer representing the new authentication level for the user.
    - `forced_scheme`: a string representing a forced user authentication scheme in JSON format to use for validating the auth level change against softlock situations instead of the user authentication scheme defined in the registry entry for the specified database. This is only applicable if `auth_level` is provided.
    - `omit_softlock_check`: a boolean indicating whether to omit the softlock check for the auth level change. If `True`, it will not perform the softlock check and will allow the auth level change even if it results in a softlock situation. This is only applicable if `auth_level` is provided.

    returns:
    - it returns a `UserModel` object representing the updated user.
    """
    if auth_level is not None and not omit_softlock_check and softlock_checker(db_id, identifier, auth_level, forced_scheme=forced_scheme):
        abort(401, description="Action would result in no more users with 'registry_patch_user_auth_scheme' permissions.") #currently not checking for user_patch_auth_level and user_post_new as is would be hierachical and thus more complex to check, but can be added in the future if needed
    
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
    """
    function `delete_user` deletes a specified user (method and value) from a specified database (db_id).

    required arguments:
    - `db_id`: a `string` representing the database ID of the registry entry corresponding to the user database to delete the user from.
    - `method`: a `string` representing the method to use for identifying the user to delete.
    - `value`: a `string` representing the identifier value to search for based on the provided identifier method to identify the user to delete.
    """
    user, app = get_user_by(db_id, method, value, full_info=True)
    if not user:
        abort(404, description="User not found.")
    if  softlock_checker(db_id):
        abort(401, description="Action would result in no more users with 'registry_patch_user_auth_scheme' permissions.") #currently not checking for user_patch_auth_level and user_post_new as is would be hierachical and thus more complex to check, but can be added in the future if needed
    with app.app_context():
        db.session.delete(user)
        db.session.commit()
        return {"message":"User deleted succesfully."}

def get_auth_token(): #retrieves the auth token from a client request
    """function `get_auth_token` retrieves the auth token from the request headers and return this if it is present, otherwise returns None."""
    token = request.headers.get("X-Auth-Token")
    if not token:
        return None
    return token

def validate_auth_token(db_id, token, bypassable=True): #checks if the user has a valid auth token
    """
    function `validate_auth_token` checks if the provided auth token is valid for the specified database.

    required arguments:
    - `db_id`: the database identifier.
    - `token`: a `string` representing the auth token to validate.

    optional arguments:
    - `bypassable`: a `boolean` indicating whether the validation can be safely bypassed for testing purposes.

    returns:
    - a `boolean` value indicating whether the provided auth token is valid for the specified registry database (`True` if valid, `False` if invalid).
    """
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
    """
    function `softlock_checker` checks if a softlock will be created under a given circumstance. Return `True` if there will be a softlock situation and `False` if there will not be a softlock situation.

    required arguments:
    - `db_id`: the registry entry to check.

    optional arguments:
    - `user_id`: a `string` representing the ID of the user whose auth level is being updated.
    - `new_auth_level`: an `integer` representing the new auth level for the specified user.
    - `forced_scheme`: a `string` representing a forced authentication scheme to use for validation.
    - `users`: a `list` of `UserModel` objects to check for softlock situations.

    returns:
    - a `boolean` value indicating whether there is a softlock situation (`True` if there is a softlock situation, `False` if there is no softlock situation).
    """
    if users is None:
        users = get_all_users(db_id)
    patched_user = None
    if user_id:
        patched_user = UserModel.query.filter_by(user_id=user_id).first()
    for user in users:
        if user_id and user == patched_user:
            user.auth_level = new_auth_level
        registry_patch_user_auth_scheme = validate_actions(db_id=db_id, primary_application="central_authorization_tool", fallback_application="central_application", primary_location="registry_patch_user_auth_scheme", fallback_location="registry_patch", user=user, forced_scheme=forced_scheme)
        if registry_patch_user_auth_scheme:
            return False
    return True

def validate_actions(db_id:str, primary_application:str, fallback_application:str, primary_location:str, fallback_location:str, user_id:str=None, auth_token:str=None, user=None, use_hierarchy:bool=False, act_on:str=None, user_is_act_on=False, act_on_is_int=False, forced_scheme:str=None, bypassable=False): #validates if the provided token allows actions at the specified location
    """
    function `validate_actions` checks if a user has sufficient permissions to perform the specific action they are trying to do. Return a `boolean` value indicating if they have sufficient permissions, `True` if they do and `False` if not.

    required arguments:
    - `db_id`: the identifier of the registry entry.
    - `primary_application`: a `string` representing the specific application that is being verified.
    - `fallback_application`: a `string` representing the generic application, used if the specific application isn't specified in the `user_auth_scheme`.
    - `primary_location`: a `string` representing the specific location that is being verified.
    - `fallback_location`: a `string` representing the generic location, used if the specific location isn't specified in the `user_auth_scheme`.

    optional arguments:
    - `user_id`: a `string` that identifies the user being verified. (exchangable with `auth_token` and `user`)
    - `auth_token`: a `string` that identifies the user being verified. (exchangable with `user_id` and `user`)
    - `user`: a `UserModel` object of the user being verified. (exchangable with `user_id` and `auth_token`)
    - `use_hierarchy`: a `boolean` indicating if hierarchy is applicable.
    - `act_on`: a `string` to identify the target user by, it represents an `user_id` unless `act_on_is_int` is `True`, in which case it represents an auth level. This field is required if use_hierarchy is `True`.
    - `user_is_act_on`: a `boolean` indicating whether `act_on` has to be the user making the request.
    - `act_on_is_int`: a `boolean` indicating whether the `act_on` value is an integer representing the auth level of the target user instead of a `string` representing the `user_id`.
    - `forced_scheme`: a `string` representing a forced user authentication scheme in JSON format to use for validation instead of the user authentication scheme defined in the registry entry for the specified database.
    - `bypassable`: a `boolean` indicating whether the validation can be bypassed for testing purposes. If `True`, it will bypass the validation and return `True` if the environment variable `TESTING` is set to "True". If `False`, it will perform the validation regardless of the environment variable.

    returns:
    - a `boolean` value indicating if the user has sufficient permissions to perform the desired action. `True` if the user has sufficient permissions, `False` if the user does not have sufficient permissions.
    """
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
    
    notation = registry["notation"]
    exceptions = registry["except"]
    if exceptions is None:
        exceptions = []
    elif type(exceptions) != list:
        abort(500, description="Invalid settings; 'except' key must be a list or None at the indent level of the registry settings.")
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
    allow_key = application_key["allow_key"]
    if type(application_key["except"]) != list and application_key["except"] is not None:
        abort(500, description="Invalid settings; 'except' key must be a list or None at the indent level of the application settings.")
    elif application_key["except"] is not None:
        exceptions = exceptions.extend(application_key["except"])
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
                try:
                    translation_key = registry["translation_key"]
                except KeyError:
                    abort(400, description="Invalid settings; missing 'translation_key' in application key.")
                user = int(translation_key[str(user.auth_level)])
            else:
                abort(400, description="Invalid auth level format for user.")
    bigger_than, smaller_than, allow, ban = unpack_settings(key=allow_key, primary_location=primary_location, fallback_location=fallback_location, notation=notation, translation_key=translation_key)
    action_allowed = False
    if str(user) in exceptions:
        action_allowed = True
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
                    try:
                        translation_key = registry["translation_key"]
                        act_on_level = int(translation_key[str(act_on_user.auth_level)])
                    except KeyError:
                        abort(400, description="Invalid settings; missing 'translation_key' in application key.")
                else:
                    abort(400, description="Invalid auth level format for act on user.")
    hierarchy = application_key["hierarchy"]
    main = hierarchy["main"]
    if type(hierarchy["except"]) != list and hierarchy["except"] is not None:
        abort(500, description="Invalid settings; 'except' key must be a list or None at the indent level of `hierarchy` in the registry settings.")
    elif hierarchy["except"] is not None:
        exceptions = exceptions.extend(hierarchy["except"]) if type(hierarchy["except"]) == list and hierarchy["except"] is not None else abort(500, description="Invalid settings; 'except' key must be a present and/or a list at the indent level of `hierarchy` in the registry settings.")
    
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
    """
    function `unpack_settings` takes a key together with the primary and fallback location keys, notation, and translation key (if needed) to unpack the settings for a specific location in the user authentication scheme defined in the registry entry for the specified database. Returns a `tuple[bigger_than, smaller_than, allow, ban]`.

    required arguments:
    - `key`: a `dictionary` representing the user authentication scheme or a specific location in the user authentication scheme to unpack the settings from.
    - `primary_location`: a `string` representing the primary location key to look for in the user authentication scheme for the specified application in the registry entry for the specified database.
    - `fallback_location`: a `string` representing the fallback location key to look for in the user authentication scheme for the specified application in the registry entry for the specified database if the primary location key is not found.
    - `notation`: a `string` representing the notation format used for the settings in the user authentication scheme. It can be either `string` or `integer`.

    optional arguments:
    - `translation_key`: a `dictionary` representing the translation key to use for translating `string` settings into `integer` values if the notation is `string`. This is required if the notation is `string` to properly translate the settings.
    - `handle_self`: a `boolean` indicating whether to evaluate 'self' when checking hierarchical permissions in the advanced hierarchy. `self` represents the user's own auth level.
    - `self`: an `integer` representing the user's own auth level to look for specific settings for if `handle_self` is set to `True`. This is required if `handle_self` is `True` to properly look for specific settings for the user's own auth level.

    returns:
    - a `tuple` containing the bigger_than, smaller_than, allow, and ban values. The bigger_than and smaller_than values can be either an `integer` or `None`, and the allow and ban values are `lists` of `integers` or `empty lists`.
    """
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
                    allow.append(int(translation_key[temp_allow[i]])) if translation_key else abort(400, description="Invalid settings; missing 'translation_key' for string notation.")
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