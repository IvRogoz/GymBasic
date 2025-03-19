# config.py
import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Replace with your actual secret key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
    SQLALCHEMY_TRACK_MODIFICATIONS = False