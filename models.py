# models.py
from extensions import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)

class ScannedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    barcode = db.Column(db.String(50), unique=True, nullable=False)
    product_name = db.Column(db.String(200), nullable=True)
    ingredients = db.Column(db.Text, nullable=True)
    nutritional_values = db.Column(db.Text, nullable=True)

class UserScans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scanned_data_id = db.Column(db.Integer, db.ForeignKey('scanned_data.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    manual_name = db.Column(db.String(200), nullable=True)
    manual_ingredients = db.Column(db.Text, nullable=True)
    manual_nutritional_values = db.Column(db.Text, nullable=True)
    picture_path = db.Column(db.String(200), nullable=True)
    scanned_data = db.relationship('ScannedData', backref='user_scans', lazy=True)
    user = db.relationship('User', backref='user_scans', lazy=True)