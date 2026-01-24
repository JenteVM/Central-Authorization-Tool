from utils.db_utils import db, generate_user_id

class UserModel(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.String(32), primary_key=True, default=generate_user_id)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    show_email = db.Column(db.Boolean, default=True)
    auth_level = db.Column(db.Integer, nullable=False)
    auth_token = db.Column(db.String(120), unique=True)
    auth_token_expiration = db.Column(db.DateTime)
    creation_date = db.Column(db.DateTime)

    def __repr__(self):
        return f"[{self.auth_level}; {self.user_id}] <User {self.username} ({self.email})>"