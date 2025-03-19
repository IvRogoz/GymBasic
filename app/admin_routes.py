from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app import db
from app.models import User, UserScans
from app.utils import superuser_required
import calendar, json
from sqlalchemy import func

admin = Blueprint('admin', __name__)

@admin.route('/dashboard')
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
            return redirect(url_for('admin.admin_dashboard'))
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

@admin.route('/delete_log/<int:log_id>', methods=['POST'])
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
    return redirect(url_for('admin.admin_dashboard', **request.args))
