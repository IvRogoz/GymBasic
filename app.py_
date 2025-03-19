from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import json
import requests
from PIL import Image
import calendar
from sqlalchemy import func

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
print(f"UPLOAD_FOLDER set to: {app.config['UPLOAD_FOLDER']}")  

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Database Models
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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superuser:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
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
        if scan.scanned_data and isinstance(scan.scanned_data.nutritional_values, str):
            try:
                scan.nutritional_values_decoded = json.loads(scan.scanned_data.nutritional_values)
            except json.JSONDecodeError:
                scan.nutritional_values_decoded = {}
        else:
            scan.nutritional_values_decoded = {}
    return render_template('dashboard.html', user_scans=user_scans)

@app.route('/manual_entry', methods=['POST'])
@login_required
def manual_entry():
    name = request.form.get('name')
    ingredients = request.form.get('ingredients')
    nutritional_values = request.form.get('nutritional_values')
    if nutritional_values:
        try:
            # json.loads instead of eval for security
            nutritional_values = json.dumps(json.loads(nutritional_values))
        except json.JSONDecodeError:
            flash("Invalid nutritional values format. Please use JSON.", "danger")
            return redirect(url_for('dashboard'))
    file = request.files.get('picture')
    picture_path = None
    if file:
        filename = secure_filename(file.filename)
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(picture_path)
        img = Image.open(picture_path)
        img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        img.save(picture_path, quality=85)
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

@app.route('/scan', methods=['POST'])
@login_required
def scan_barcode():
    picture_path = None
    barcode = request.form.get('barcode')

    if 'photo' not in request.files:
        return jsonify({"error": "No photo provided"}), 400
    
    photo = request.files['photo']
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    if barcode:  # Barcode scan mode
        scanned_data = ScannedData.query.filter_by(barcode=barcode).first()
        filename = f"barcode_{barcode}_{timestamp}.jpg"
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"Saving barcode photo to: {picture_path}") 
        img = Image.open(photo)
        img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        img.save(picture_path, quality=85)

        if not scanned_data:
            response = requests.get(f"https://world.openfoodfacts.org/api/v0/product/{barcode}.json")
            if response.status_code == 200 and response.json().get("status") == 1:
                product_data = response.json()["product"]
                product_name = product_data.get("product_name", "Unknown Product")
                ingredients = product_data.get("ingredients_text", "Unknown Ingredients")
                nutrition = product_data.get("nutriments", {})
                scanned_data = ScannedData(
                    barcode=barcode,
                    product_name=product_name,
                    ingredients=ingredients,
                    nutritional_values=json.dumps({
                        "energy_100g": nutrition.get("energy_100g", "N/A"),
                        "carbohydrates_100g": nutrition.get("carbohydrates_100g", "N/A"),
                        "sugars_100g": nutrition.get("sugars_100g", "N/A"),
                        "fat_100g": nutrition.get("fat_100g", "N/A"),
                        "proteins_100g": nutrition.get("proteins_100g", "N/A"),
                        "salt_100g": nutrition.get("salt_100g", "N/A")
                    })
                )
                db.session.add(scanned_data)
                db.session.commit()
            else:
                return jsonify({"error": "Product not found"}), 404
        
        user_scan = UserScans(
            user_id=current_user.id,
            scanned_data_id=scanned_data.id,
            picture_path=filename 
        )
        db.session.add(user_scan)
        db.session.commit()
        print(f"Saved to DB: {filename}")  
        
        return jsonify({
            "product_name": scanned_data.product_name,
            "ingredients": scanned_data.ingredients,
            "nutrition": json.loads(scanned_data.nutritional_values),
            "photo_url": url_for('uploaded_file', filename=filename)
        })
    
    else:  # Manual photo capture mode
        filename = f"manual_{timestamp}.jpg"
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"Saving manual photo to: {picture_path}")
        img = Image.open(photo)
        img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        img.save(picture_path, quality=85)
        
        user_scan = UserScans(
            user_id=current_user.id,
            manual_name=f"Manual_Photo_{timestamp}",
            picture_path=filename 
        )
        db.session.add(user_scan)
        db.session.commit()
        print(f"Saved to DB: {filename}") 
        
        return jsonify({"photo_url": url_for('uploaded_file', filename=filename)})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(f"Attempting to serve file: {file_path}")  
    if os.path.exists(file_path):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        print(f"File not found: {file_path}")
        return jsonify({"error": "File not found"}), 404

@app.route('/debug/uploads')
@login_required
def debug_uploads():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify({"files": files})

@app.route('/photo', methods=['POST'])
@login_required
def photo():
    file = request.files.get('photo')
    if not file:
        flash("No photo uploaded.", "danger")
        return redirect(url_for('dashboard'))
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"photo_{timestamp}.jpg"
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(picture_path)
    img = Image.open(picture_path)
    img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
    img.save(picture_path, quality=85)
    user_scan = UserScans(
        user_id=current_user.id,
        manual_name=f"Photo_{timestamp}",
        picture_path=picture_path
    )
    db.session.add(user_scan)
    db.session.commit()
    flash("Photo saved successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/admin_dashboard')
@login_required
@superuser_required
def admin_dashboard():
    year = request.args.get('year')
    month = request.args.get('month')
    search = request.args.get('search')
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_order = request.args.get('sort_order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    month_names = {i: calendar.month_name[i] for i in range(1, 13)}

    if year and month:
        try:
            year_int = int(year)
            month_int = int(month)
            if month_int < 1 or month_int > 12:
                raise ValueError
            logs = UserScans.query.filter(
                func.strftime('%Y', UserScans.timestamp) == year,
                func.strftime('%m', UserScans.timestamp) == f'{month_int:02d}'
            )
        except ValueError:
            flash('Invalid year or month.', 'danger')
            return redirect(url_for('admin_dashboard'))
    else:
        logs = UserScans.query

    if search:
        logs = logs.join(User).filter(User.username.ilike(f'%{search}%'))

    if sort_by == 'timestamp':
        order = UserScans.timestamp.desc() if sort_order == 'desc' else UserScans.timestamp.asc()
    elif sort_by == 'username':
        order = User.username.desc() if sort_order == 'desc' else User.username.asc()
        logs = logs.join(User)
    else:
        order = UserScans.timestamp.desc()
    logs = logs.order_by(order)

    pagination = logs.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items

    for log in logs:
        if log.scanned_data and isinstance(log.scanned_data.nutritional_values, str):
            try:
                log.nutritional_values_decoded = json.loads(log.scanned_data.nutritional_values)
            except json.JSONDecodeError:
                log.nutritional_values_decoded = {}
        else:
            log.nutritional_values_decoded = {}

    if not year or not month:
        available_months = db.session.query(
            func.strftime('%Y', UserScans.timestamp).label('year'),
            func.strftime('%m', UserScans.timestamp).label('month')
        ).distinct().order_by('year', 'month').all()
        return render_template('admin_dashboard_months.html', 
                              available_months=available_months, 
                              month_names=month_names)

    return render_template('admin_dashboard.html', 
                          logs=logs, 
                          pagination=pagination, 
                          year=year, 
                          month=month, 
                          month_name=month_names[month_int], 
                          search=search, 
                          sort_by=sort_by, 
                          sort_order=sort_order)

@app.route('/delete_log/<int:log_id>', methods=['POST'])
@login_required
@superuser_required
def delete_log(log_id):
    log = UserScans.query.get(log_id)
    if log:
        db.session.delete(log)
        db.session.commit()
        flash('Log deleted successfully.', 'success')
    else:
        flash('Log not found.', 'danger')
    return redirect(url_for('admin_dashboard', **request.args))

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