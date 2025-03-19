from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, send_from_directory, current_app
from flask_login import login_required, login_user, logout_user, current_user
from app import db, bcrypt
from app.models import User, UserScans, ScannedData
from PIL import Image
from datetime import datetime
from werkzeug.utils import secure_filename
import os, json, requests

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            if user.is_superuser:
                return redirect(url_for('admin.admin_dashboard'))
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))

@main.route('/dashboard')
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

@main.route('/manual_entry', methods=['POST'])
@login_required
def manual_entry():
    name = request.form.get('name')
    ingredients = request.form.get('ingredients')
    nutritional_values = request.form.get('nutritional_values')
    if nutritional_values:
        try:
            nutritional_values = json.dumps(json.loads(nutritional_values))
        except json.JSONDecodeError:
            flash("Invalid nutritional values format. Please use JSON.", "danger")
            return redirect(url_for('main.dashboard'))
    file = request.files.get('picture')
    picture_path = None
    if file:
        filename = secure_filename(file.filename)
        upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
        picture_path = os.path.join(upload_folder, filename)
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
    return redirect(url_for('main.dashboard'))

@main.route('/scan', methods=['POST'])
@login_required
def scan_barcode():
    picture_path = None
    barcode = request.form.get('barcode')

    if 'photo' not in request.files:
        return jsonify({"error": "No photo provided"}), 400
    
    photo = request.files['photo']
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
    
    if barcode:  # Barcode scan mode
        scanned_data = ScannedData.query.filter_by(barcode=barcode).first()
        filename = f"barcode_{barcode}_{timestamp}.jpg"
        picture_path = os.path.join(upload_folder, filename)
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
        
        return jsonify({
            "product_name": scanned_data.product_name,
            "ingredients": scanned_data.ingredients,
            "nutrition": json.loads(scanned_data.nutritional_values),
            "photo_url": url_for('main.uploaded_file', filename=filename)
        })
    
    else:  # Manual photo capture mode
        filename = f"manual_{timestamp}.jpg"
        picture_path = os.path.join(upload_folder, filename)
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
        
        return jsonify({"photo_url": url_for('main.uploaded_file', filename=filename)})

@main.route('/uploads/<filename>')
def uploaded_file(filename):
    upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
    file_path = os.path.join(upload_folder, filename)
    if os.path.exists(file_path):
        return send_from_directory(upload_folder, filename)
    else:
        return jsonify({"error": "File not found"}), 404

@main.route('/debug/uploads')
@login_required
def debug_uploads():
    upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
    files = os.listdir(upload_folder)
    return jsonify({"files": files})

@main.route('/photo', methods=['POST'])
@login_required
def photo():
    file = request.files.get('photo')
    if not file:
        flash("No photo uploaded.", "danger")
        return redirect(url_for('main.dashboard'))
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"photo_{timestamp}.jpg"
    upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
    picture_path = os.path.join(upload_folder, filename)
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
    return redirect(url_for('main.dashboard'))
