import os
from dotenv import load_dotenv
from models.registry_models import RegistryModel
from utils.db_utils import db, create_user_db, generate_AO_addition_token, generate_ids
from sqlalchemy.exc import IntegrityError
from flask import request

def get_registry_entries(): #gets all registry entries
    return RegistryModel.query.all()

def get_registry_entry_by_id(db_id:str): #gets a specific registry entry
    return RegistryModel.query.filter_by(db_id=db_id).first()

def create_registry_entry(app_name:str): #creates a new registry entry
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
        return new_entry
    except IntegrityError:
        db.session.rollback()
        return None

def patch_registry_entry(db_id, app_name=None, allowed_origins=None, AO_addition_token=None): #updates an existing registry entry
    registry = get_registry_entry_by_id(db_id)
    if app_name:
        registry.app_name = app_name
    if allowed_origins:
        registry.allowed_origins = allowed_origins
        registry.AO_addition_token = None
    if AO_addition_token:
        registry.AO_addition_token = AO_addition_token
    db.session.commit()
    return registry

def get_reg_token(): #returns the AO addition token for a registry entry
    token = request.headers.get("AO-Addition-Token")
    if not token:
        return None
    return token

def get_db_id():
    db_id = request.headers.get("db-id")
    if not db_id:
        print("No db_id provided")
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