import os
import json
from dotenv import load_dotenv
from models.registry_models import RegistryModel
from utils.db_utils import db, create_user_db, generate_AO_addition_token, generate_ids
from services.user_service import get_all_users, softlock_checker, update_user
from sqlalchemy.exc import IntegrityError
from flask import request, abort

def get_registry_entries(load_for_return=False): #gets all registry entries
    registries = RegistryModel.query.all()
    if load_for_return:
        for registry in registries:
            registry.user_auth_scheme = json.loads(registry.user_auth_scheme)
    return registries

def get_registry_entry_by_id(db_id:str, load_for_return=False): #gets a specific registry entry
    registry = RegistryModel.query.filter_by(db_id=db_id).first()
    if registry and load_for_return:
        registry.user_auth_scheme = json.loads(registry.user_auth_scheme)
    return registry

def create_registry_entry(app_name:str, load_for_return=False): #creates a new registry entry
    db_id, db_secret = generate_ids()
    new_entry = RegistryModel(
        db_id=db_id,
        db_secret=db_secret,
        app_name=app_name,
        user_auth_scheme='{"notation": "integer", "allow_key": {"else": {"smaller_than": "5", "bigger_than": null, "allow": ["5"], "ban": null}}, "hierarchy": {"main": "advanced", "advanced": {"else": {"else": {"smaller_than": null, "bigger_than": "self", "allow": null, "ban": null}}}, "except": ["5"]}}',
        AO_addition_token=generate_AO_addition_token(),
    )
    
    try:
        db.session.add(new_entry)
        db.session.commit()
        create_user_db(db_secret)
        new_entry.user_auth_scheme = json.loads(new_entry.user_auth_scheme) if load_for_return else new_entry.user_auth_scheme
        return new_entry
    except IntegrityError:
        db.session.rollback()
        return None

def patch_registry_entry(db_id, app_name=None, allowed_origins=None, AO_addition_token=None, auth_scheme=None, translation=None, authorized=None, load_for_return=False): #updates an existing registry entry
    registry = get_registry_entry_by_id(db_id)
    if app_name:
        registry.app_name = app_name
    if allowed_origins:
        registry.allowed_origins = allowed_origins
        registry.AO_addition_token = None
    if AO_addition_token:
        registry.AO_addition_token = AO_addition_token
    if authorized is not None:
        registry.authorized = authorized
    if auth_scheme or translation:
        users = get_all_users(db_id)
        if translation:
            if isinstance(translation, str):
                translation = json.loads(translation)
            for user in users:
                try:
                    user.auth_level = translation[str(user.auth_level)]
                except KeyError:
                    pass
        if softlock_checker(db_id, forced_scheme=auth_scheme, users=users):
            abort(401, description="Action would result in no more users with 'User Patch Auth Level (uPatchAL)' or 'Registry Patch Validate Actions (rPatchVA)' permissions.")
        registry.user_auth_scheme = auth_scheme if auth_scheme else registry.user_auth_scheme
        if translation:
            for user in users:
                update_user(db_id, user.user_id, auth_level=user.auth_level, omit_softlock_check=True)
    db.session.commit()
    registry.user_auth_scheme = json.loads(str(registry.user_auth_scheme)) if load_for_return else registry.user_auth_scheme
    print(registry) #avoid lazy loading issues
    return registry

def get_reg_token(): #returns the AO addition token for a registry entry
    token = request.headers.get("AO-Addition-Token")
    if not token:
        return None
    return token

def get_db_id():
    db_id = request.headers.get("db-id")
    if not db_id:
        return None
    return db_id

def get_allowed_origins(partial=False): #returns a list of allowed origins
    with db.engine.connect() as connection:
        result = connection.execute(
            db.select(RegistryModel.allowed_origins).where(RegistryModel.authorized == True)
        )
        if result:
            try:
                authList = [
                    origin.strip()
                    for row in result
                    for origin in row[0].split(",")
                    if origin.strip()
                ]
            except AttributeError:
                authList = []
            load_dotenv()
            ALLOWED_REGISTRY_CREATORS = os.getenv("ALLOWED_REGISTRY_CREATORS")
            allowed_registry_creators_list = [origin.strip() for origin in ALLOWED_REGISTRY_CREATORS.split(",") if origin.strip()]
            for check_for_dupes in allowed_registry_creators_list:
                if check_for_dupes not in authList:
                    authList.append(check_for_dupes)
            if partial:
                return ALLOWED_REGISTRY_CREATORS
            else:
                return authList

def check_post_level_auth(db_id):
    if not db_id:
        return False
    registry_entry = get_registry_entry_by_id(db_id)
    if not registry_entry or not registry_entry.allowed_origins:
        return False
    allowed_origins = registry_entry.allowed_origins.split(",")
    if allowed_origins:
        allowed_origins = [origin.strip() for origin in allowed_origins]
        origin = request.headers.get("Origin")
        if origin not in allowed_origins or origin is None:
            return False
        return True
    else:
        return False
    
def check_get_level_auth(db_id):
    load_dotenv()
    testing = os.getenv("TESTING")
    if testing == "True":
        return True
    if not db_id:
        return False
    registry_entry = get_registry_entry_by_id(db_id)
    allowed_origins = [origin.strip() for origin in registry_entry.allowed_origins.split(",") if origin.strip()]
    ALLOWED_BACKEND_ACCESS = get_allowed_origins(partial=True)
    allowed_registry_creators_list = [origin.strip() for origin in ALLOWED_BACKEND_ACCESS.split(",") if origin.strip()]
    for check_for_dupes in allowed_registry_creators_list:
        if check_for_dupes not in allowed_origins:
            allowed_origins.append(check_for_dupes)
    origin = request.headers.get("Origin")
    if origin not in allowed_origins or origin is None:
        return False
    return True