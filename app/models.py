from . import db
import uuid

class Pastebin(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID for filename
    filename = db.Column(db.String(256), nullable=False)
    delete_on_view = db.Column(db.Boolean, default=False)
    delete_after = db.Column(db.Integer, nullable=True)  # Minutes
    created_at = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('pastebins', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
