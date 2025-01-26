from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import json
from collections import defaultdict

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = './uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)  # Superuser field

class ScannedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    barcode = db.Column(db.String(50), unique=True, nullable=False)
    product_name = db.Column(db.String(200), nullable=True)
    ingredients = db.Column(db.Text, nullable=True)
    nutritional_values = db.Column(db.Text, nullable=True)

class UserScans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scanned_data_id = db.Column(db.Integer, db.ForeignKey('scanned_data.id'), nullable=True)  # Nullable for manual entry
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    manual_name = db.Column(db.String(200), nullable=True)
    manual_ingredients = db.Column(db.Text, nullable=True)
    manual_nutritional_values = db.Column(db.Text, nullable=True)
    picture_path = db.Column(db.String(200), nullable=True)

    scanned_data = db.relationship('ScannedData', backref='user_scans', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

# Decorators
def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superuser:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            # Redirect based on user type
            if user.is_superuser:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_scans = UserScans.query.filter_by(user_id=current_user.id).order_by(UserScans.timestamp.desc()).all()

    for scan in user_scans:
        if scan.scanned_data and scan.scanned_data.nutritional_values:
            print(f"Product: {scan.scanned_data.product_name}")
            print(f"Nutritional Values: {scan.scanned_data.nutritional_values}")

            # Parse nutritional_values if it's a string representation of a dictionary
            if isinstance(scan.scanned_data.nutritional_values, str):
                try:
                    scan.scanned_data.nutritional_values = eval(scan.scanned_data.nutritional_values)
                except Exception as e:
                    print(f"Error parsing nutritional_values for scan {scan.id}: {e}")
                    scan.scanned_data.nutritional_values = {}
            elif isinstance(scan.scanned_data.nutritional_values, dict):
                print("Nutritional Values are a valid dictionary.")
            else:
                print("Unexpected type for nutritional_values.")

    return render_template('dashboard.html', user_scans=user_scans)




@app.route('/admin')
@login_required
@superuser_required
def admin_dashboard():
    user_scans = UserScans.query.order_by(UserScans.timestamp.desc()).all()
    grouped_logs = {}

    for scan in user_scans:
        user = db.session.get(User, scan.user_id)
        if not user:
            continue

        if user.username not in grouped_logs:
            grouped_logs[user.username] = []

        # Debugging: Print raw nutritional values
        if scan.scanned_data and scan.scanned_data.nutritional_values:
            print(f"  Product: {scan.scanned_data.product_name}")
            print(f"  Nutritional Values (raw): {scan.scanned_data.nutritional_values}")

        # Ensure nutritional_values is a dictionary
        if scan.scanned_data and scan.scanned_data.nutritional_values:
            if not isinstance(scan.scanned_data.nutritional_values, dict):
                try:
                    # Attempt to parse if it's a string
                    scan.scanned_data.nutritional_values = eval(scan.scanned_data.nutritional_values)
                    print(f"  Nutritional Values (parsed): {scan.scanned_data.nutritional_values}")
                except Exception as e:
                    print(f"  Error parsing nutritional_values for scan {scan.id}: {e}")
                    scan.scanned_data.nutritional_values = {}
            else:
                print(f"  Nutritional Values are already a dictionary.")

        grouped_logs[user.username].append(scan)

    return render_template('admin_dashboard.html', grouped_logs=grouped_logs)


















@app.route('/scan', methods=['POST'])
@login_required
def scan_barcode():
    barcode = request.json.get('barcode')
    scanned_data = ScannedData.query.filter_by(barcode=barcode).first()
    if not scanned_data:
        scanned_data = ScannedData(
            barcode=barcode,
            product_name="Sample Product",
            ingredients="Sample Ingredients",
            nutritional_values="Sample Nutritional Values"
        )
        db.session.add(scanned_data)
        db.session.commit()

    user_scan = UserScans(
        user_id=current_user.id,
        scanned_data_id=scanned_data.id
    )
    db.session.add(user_scan)
    db.session.commit()

    return jsonify({
        "message": "Nutrition data logged!",
        "product_name": scanned_data.product_name,
        "ingredients": scanned_data.ingredients,
        "nutritional_values": scanned_data.nutritional_values
    })

@app.route('/manual_entry', methods=['POST'])
@login_required
def manual_entry():
    name = request.form.get('name')
    ingredients = request.form.get('ingredients')
    nutritional_values = request.form.get('nutritional_values')
    file = request.files.get('picture')
    picture_path = None
    if file:
        filename = secure_filename(file.filename)
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(picture_path)

    user_scan = UserScans(
        user_id=current_user.id,
        manual_name=name,
        manual_ingredients=ingredients,
        manual_nutritional_values=nutritional_values,
        picture_path=picture_path
    )
    db.session.add(user_scan)
    db.session.commit()

    flash("Manual entry saved successfully!", "success")
    return redirect(url_for('dashboard'))

def create_superuser(username, email, password):
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    superuser = User(username=username, email=email, password=hashed_password, is_superuser=True)
    db.session.add(superuser)
    db.session.commit()
    print(f"Superuser '{username}' created successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
