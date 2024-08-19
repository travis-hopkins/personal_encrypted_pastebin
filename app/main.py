import os
import time
import uuid
import logging
import secrets
import threading
from flask import Flask, render_template, request, jsonify, url_for, send_file, redirect, flash, session
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from itsdangerous import URLSafeTimedSerializer
from requests_oauthlib import OAuth2Session
from datetime import datetime
from dotenv import load_dotenv

# Set environment variable for OAuth insecure transport
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Load environment variables from .env file
load_dotenv('/opt/pastebin-app/app/config.env')

# Initialize Flask app
app = Flask(__name__, static_folder='/opt/pastebin-app/static', template_folder='/opt/pastebin-app/templates')

# Secret key for sessions
app.secret_key = os.getenv('SECRET_KEY')

# Ensure instance directory exists
instance_folder = '/opt/pastebin-app/instance'
if not os.path.exists(instance_folder):
    os.makedirs(instance_folder)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_folder, "pastebin.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Allow NULL for password
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    registration_method = db.Column(db.String, nullable=True)
    login_method = db.Column(db.String, nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)

    def get_id(self):
        return str(self.id)  # Return the ID as a string

    def __repr__(self):
        return f'<User {self.email}>'

class Pastebin(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # UUID as string
    content = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=True)
    delete_after = db.Column(db.Integer, nullable=True)  # Time in minutes
    delete_on_view = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.String, default=datetime.utcnow().isoformat)  # ISO 8601 string format
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='pastebins')
    encryption_key = db.Column(db.String(255), nullable=True)  # Store the encryption key

# Initialize Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"success": False, "error": "Unauthorized"}), 401

# OAuth Configuration
client_id = os.getenv('OAUTH_CLIENT_ID')
client_secret = os.getenv('OAUTH_CLIENT_SECRET')
authorization_base_url = os.getenv('OAUTH_AUTHORIZATION_BASE_URL')
token_url = os.getenv('OAUTH_TOKEN_URL')
redirect_uri = os.getenv('OAUTH_REDIRECT_URI')

# Handle OAuth scope
oauth_scope = os.getenv('OAUTH_SCOPE')
if oauth_scope is None:
    app.logger.error('OAUTH_SCOPE environment variable is not set.')
    raise ValueError('OAUTH_SCOPE environment variable is not set.')
scope = oauth_scope.split(',')

# Custom Jinja2 filter for formatting datetime
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')  # Adjust format to match ISO 8601
        except ValueError:
            # Handle the case where the string does not match the expected format
            return value
    return value.strftime(format)


# Create database tables if they do not exist
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    app.logger.debug(f'Current user: {current_user}')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('All fields are required.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        token = serializer.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        msg = Message('Confirm Your Email', recipients=[email])
        msg.html = html
        mail.send(msg)

        flash('A confirmation email has been sent to your email address.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_active:
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Please confirm your email before logging in.')
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user.is_active:
        flash('Account already confirmed. Please login.')
    else:
        user.is_active = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!')

    return redirect(url_for('login'))

@app.route('/login/google')
def login_google():
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = google.authorization_url(authorization_base_url, access_type='offline', prompt='select_account')
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        google = OAuth2Session(client_id, state=session.get('oauth_state'), redirect_uri=redirect_uri)
        token = google.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)
        session['google_token'] = token

        user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
        email = user_info.get('email')

        if not email:
            raise ValueError("No email found in user info")

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                password=None,
                is_active=True,
                registration_method='Google',
                login_method='OAuth'
            )
            db.session.add(user)
            db.session.commit()

        if user.is_blocked:
            session['popup_message'] = 'Your account is blocked. Please contact support.'
            return redirect(url_for('blocked'))

        login_user(user)
        app.logger.debug(f'User {user.email} logged in successfully.')
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error during OAuth callback: {str(e)}")
        return jsonify({"success": False, "error": f"Error during OAuth callback: {str(e)}"}), 500

@app.route('/logout')
@login_required
def logout():
    print(f"Logging out user: {current_user.id}")
    logout_user()
    session.clear()  # Ensure session is cleared
    return redirect(url_for('index'))

@app.route('/paste', methods=['POST'])
@login_required
def create_paste():
    data = request.get_json()
    content = data.get('content')
    delete_on_view = data.get('delete_on_view', False)
    
    try:
        delete_after = int(data.get('delete_after', 0))
    except ValueError:
        app.logger.warning("Invalid delete_after value, not an integer.")
        return jsonify({'error': 'Invalid delete after value.'}), 400

    allowed_values = {0, 5, 10, 30, 60, 300, 1440, 10080}
    
    if delete_after not in allowed_values:
        app.logger.warning(f"Invalid delete after value: {delete_after}")
        return jsonify({'error': 'Invalid delete after value.'}), 400

    # Generate a hexadecimal encryption key (64 characters for 32 bytes)
    encryption_key = secrets.token_hex(32)
    paste_id = str(uuid.uuid4())  # Generate a new UUID as a string

    # Create the new Pastebin entry
    new_paste = Pastebin(
        id=paste_id,  # Store UUID as string
        content=content,
        user_id=current_user.id,
        encryption_key=encryption_key,  # Store as hexadecimal string
        delete_after=delete_after,
        delete_on_view=delete_on_view,
        created_at=datetime.utcnow().isoformat()  # Use ISO 8601 string format
    )

    try:
        db.session.add(new_paste)
        db.session.commit()
        app.logger.info(f"Paste created successfully with ID: {paste_id}")
    except Exception as e:
        app.logger.error(f"Error committing new paste to the database: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error. Could not save paste.'}), 500

    if delete_after > 0:
        app.logger.info(f"Setting up timed deletion for pastebin {paste_id} after {delete_after} minutes")
        threading.Timer(delete_after * 60, delete_paste, args=(paste_id,)).start()

    paste_url = url_for('view_paste', paste_id=paste_id, key=encryption_key, _external=True)
    app.logger.debug(f"Paste URL generated: {paste_url}")

    return jsonify({'url': paste_url})



@app.route('/paste/<paste_id>/<key>', methods=['GET'])
def view_paste(paste_id, key):
    try:
        # Fetch the pastebin entry from the database
        paste = Pastebin.query.filter_by(id=paste_id, encryption_key=key).first_or_404()
        
        if paste.delete_on_view:
            # Immediately delete the paste after viewing
            db.session.delete(paste)
            db.session.commit()
            app.logger.info(f"Paste {paste_id} deleted after viewing.")
        
        app.logger.debug(f"Paste fetched: {paste}")
        # Render the paste view
        return render_template('view-paste.html', paste=paste)
    except Exception as e:
        app.logger.error(f"Error fetching paste: {e}")
        return jsonify({'error': 'Internal server error. Could not fetch paste.'}), 500
    
def delete_paste(paste_id):
    try:
        paste = Pastebin.query.get(paste_id)
        if paste:
            db.session.delete(paste)
            db.session.commit()
            app.logger.info(f"Paste {paste_id} deleted after time expiry.")
    except Exception as e:
        app.logger.error(f"Error during timed paste deletion: {str(e)}")




@app.route('/my_pastebins')
@login_required
def my_pastebins():
    pastebins = Pastebin.query.filter_by(user_id=current_user.id).order_by(Pastebin.created_at.desc()).all()
    return render_template('my-pastebins.html', pastebins=pastebins)

@app.route('/delete_pastebin/<paste_id>/<key>', methods=['POST'])
@login_required
def delete_pastebin(paste_id, key):
    try:
        pastebin = Pastebin.query.filter_by(id=paste_id, user_id=current_user.id, encryption_key=key).first()
        if pastebin:
            db.session.delete(pastebin)
            db.session.commit()
            app.logger.info(f"Pastebin {paste_id} deleted successfully.")
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Pastebin not found or permission denied'})
    except Exception as e:
        app.logger.error(f"Error during pastebin deletion: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/clear_pastebins', methods=['POST'])
@login_required
def clear_pastebins():
    try:
        # Delete all pastebins for the current user
        num_deleted = Pastebin.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash(f'All your pastebins have been deleted. (Deleted {num_deleted} pastebins)', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error clearing pastebins: {str(e)}', exc_info=True)
        flash(f'Error clearing pastebins: {str(e)}', 'danger')
    
    return redirect(url_for('my_pastebins'))

@app.route('/users')
@login_required
def users():
    # Ensure the current user is an admin or authorized to view this page
    if not current_user.is_admin:
        return redirect(url_for('index'))

    users = User.query.all()  # Fetch all users from the database
    return render_template('users.html', users=users)

@app.route('/set_admin/<int:user_id>', methods=['POST'])
@login_required
def set_admin(user_id):
    # Ensure only admins can perform this action
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if user:
        user.is_admin = True
        db.session.commit()
        return redirect(url_for('users'))
    return jsonify({"success": False, "error": "User not found"}), 404

@app.route('/remove_admin/<int:user_id>', methods=['POST'])
@login_required
def remove_admin(user_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if user:
        user.is_admin = False
        db.session.commit()
        flash('User has been removed from admin privileges.')
        return redirect(url_for('users'))
    return jsonify({"success": False, "error": "User not found"}), 404

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('users'))

@app.route('/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_blocked = True
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_blocked = False
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/blocked')
def blocked():
    message = session.pop('popup_message', None)
    return render_template('blocked.html', message=message)

# Route to handle user actions in the user management page
@app.route('/manage_user/<int:user_id>', methods=['POST'])
@login_required
def manage_user(user_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    action = request.form.get('action')
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if action == 'block':
        user.is_blocked = True
    elif action == 'unblock':
        user.is_blocked = False
    elif action == 'delete':
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('users'))
    elif action == 'set_admin':
        user.is_admin = True
    elif action == 'remove_admin':
        user.is_admin = False
    else:
        return jsonify({"success": False, "error": "Invalid action"}), 400

    db.session.commit()
    return redirect(url_for('users'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)