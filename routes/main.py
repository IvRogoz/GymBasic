# routes/main.py
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_from_directory, jsonify, current_app
from flask_login import login_required, current_user
from models import db, UserScans
import json
from datetime import datetime
from PIL import Image
from werkzeug.utils import secure_filename
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('home.html')

@main_bp.route('/dashboard')
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

@main_bp.route('/manual_entry', methods=['POST'])
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
        picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
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

@main_bp.route('/photo', methods=['POST'])
@login_required
def photo():
    file = request.files.get('photo')
    if not file:
        flash("No photo uploaded.", "danger")
        return redirect(url_for('main.dashboard'))
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"photo_{timestamp}.jpg"
    picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
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

@main_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
    else:
        return jsonify({"error": "File not found"}), 404

@main_bp.route('/debug/uploads')
@login_required
def debug_uploads():
    files = os.listdir(current_app.config['UPLOAD_FOLDER'])
    return jsonify({"files": files})