# app.py
from flask import Flask
from config import Config
from extensions import db, bcrypt, login_manager, migrate
from models import User

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
migrate.init_app(app, db)

# Register blueprints
from routes.auth import auth_bp
from routes.main import main_bp
from routes.scan import scan_bp
from routes.admin import admin_bp

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(admin_bp)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def create_superuser(username, email, password):
    with app.app_context():
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            return
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_superuser = User(username=username, email=email, password=hashed_password, is_superuser=True)
        db.session.add(new_superuser)
        db.session.commit()
        print(f"Superuser '{username}' created successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin',
                         email='admin@example.com',
                         password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                         is_superuser=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)