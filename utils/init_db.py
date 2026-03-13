"""
module `init_db` defines the function for initializing the registry database.

functions:
- `init_registry_database`: initializes the registry database, base instance, and base instance user.
"""
import os
from flask import Flask, abort
from flask_restful import Api
from datetime import datetime
from models.registry_models import RegistryModel
from models.user_model import UserModel
from utils.db_utils import db, generate_ids, generate_user_id, create_user_db, connect_with_user_db
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

def init_registry_database(): #initializes the registry database, base instance, and base instance user so there is always a location to create new databases
    """function `init_registry_database` initializes the registry database, base instance, and base instance user. Returns `db_id` on success or an `409 error` if the registry database already exists."""
    global db
    load_dotenv()
    instance_path = os.path.join(os.getcwd(), "instance")
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)

    db_path = os.path.join(instance_path, os.getenv("DB_REGISTRY"))
    if not os.path.exists(db_path):
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(app)

        DEFAULT_ALLOWED_ORIGIN = os.getenv("ALLOWED_REGISTRY_CREATORS")
        with app.app_context():
            db.create_all()
            if not RegistryModel.query.first():
                db_id, db_secret = generate_ids()
                new_entry = RegistryModel(
                    db_id=db_id,
                    db_secret=db_secret,
                    app_name="DefaultAllowedOrigin",
                    allowed_origins=DEFAULT_ALLOWED_ORIGIN,
                    user_auth_scheme=os.getenv("DEFAULT_AUTH_SCHEME"),
                    authorized=True
                )
                db.session.add(new_entry)
                db.session.commit()
                create_user_db(db_secret)
                db, app = connect_with_user_db(db_id)
                with app.app_context():
                    username=os.getenv("USERNAME")
                    email=os.getenv("EMAIL")
                    password=generate_password_hash(os.getenv("PASSWORD"))
                    new_user = UserModel(
                        user_id=generate_user_id(),
                        username=username,
                        email=email,
                        password_hash=password,
                        auth_level=5,
                        creation_date=datetime.now(),
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    return db_id

    else:
        abort(409, description="Registry database already exists. Initialization skipped.")