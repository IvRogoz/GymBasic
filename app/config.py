import os

class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    # Define the upload folder relative to the static folder.
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
