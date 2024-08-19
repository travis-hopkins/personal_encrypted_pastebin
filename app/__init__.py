from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app = Flask(__name__, template_folder='../templates')  # Adjust path if needed
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your-database.db'  # Update as needed
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with your secret key
    app.config['MAIL_SERVER'] = 'smtp.example.com'  # Update as needed
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = 'your-email@example.com'  # Update as needed
    app.config['MAIL_PASSWORD'] = 'your-email-password'  # Update as needed
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False

    db.init_app(app)
    mail.init_app(app)

    from .routes import bp as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
