from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superuser:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function

def create_superuser(username, email, password):
    from app import create_app, db, bcrypt
    from app.models import User
    app = create_app()
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
