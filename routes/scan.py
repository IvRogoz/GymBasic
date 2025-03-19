# routes/scan.py
from flask import Blueprint, jsonify, request, url_for, current_app
from flask_login import login_required, current_user
from models import db, ScannedData, UserScans
import requests
import json
from datetime import datetime
from PIL import Image
from werkzeug.utils import secure_filename
import os

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan', methods=['POST'])
@login_required
def scan_barcode():
    barcode = request.form.get('barcode')
    if 'photo' not in request.files:
        return jsonify({"error": "No photo provided"}), 400
    
    photo = request.files['photo']
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    if barcode:  # Barcode scan mode
        scanned_data = ScannedData.query.filter_by(barcode=barcode).first()
        filename = f"barcode_{barcode}_{timestamp}.jpg"
        picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
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
        picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
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