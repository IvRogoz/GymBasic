from app import create_app, db, bcrypt
from app.models import User

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                is_superuser=True
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
