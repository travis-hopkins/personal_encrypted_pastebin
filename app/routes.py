from flask import Flask, render_template, request, jsonify, url_for, send_file, redirect, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from flask_mail import Message, Mail
from itsdangerous import URLSafeSerializer
from requests_oauthlib import OAuth2Session
import os
import uuid
import time
import threading
from .models import Pastebin, User  # Ensure you import User as well
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Config for email and OAuth
mail = Mail(app)
serializer = URLSafeSerializer('your-secret-key')  # Replace 'your-secret-key' with your actual secret key
client_id = 'your-client-id'  # Replace with your Google OAuth client ID
client_secret = 'your-client-secret'  # Replace with your Google OAuth client secret
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
redirect_uri = 'http://localhost:5000/callback'  # Replace with your redirect URI
scope = ['https://www.googleapis.com/auth/userinfo.email']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/paste', methods=['POST'])
def create_paste():
    content = request.json.get('content')
    if not content:
        return jsonify({'error': 'Content is required'}), 400
    new_paste = Pastebin(id=str(uuid.uuid4()), content=content)  # Ensure ID is a UUID
    db.session.add(new_paste)
    db.session.commit()
    return jsonify({'url': url_for('view_paste', paste_id=new_paste.id, _external=True)})

@app.route('/paste/<paste_id>')
def view_paste(paste_id):
    paste = Pastebin.query.get_or_404(paste_id)
    return render_template('view_paste.html', paste=paste)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = str(uuid.uuid4()) + '.png'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        delete_after_minutes = request.form.get('deleteAfter', type=int)
        allowed_values = {5, 10, 30, 60, 300, 1440, 10080}
        if delete_after_minutes not in allowed_values:
            return jsonify({'error': 'Invalid delete after value.'}), 400

        delete_on_view = request.form.get('deleteOnView') == 'true'

        pastebin = Pastebin(
            id=filename,
            filename=filename,
            delete_after=delete_after_minutes,
            delete_on_view=delete_on_view,
            created_at=time.time(),
            user_id=current_user.id
        )
        db.session.add(pastebin)
        db.session.commit()

        if delete_after_minutes:
            threading.Timer(delete_after_minutes * 60, delete_file, args=(file_path,)).start()

        file_url = url_for('view_file', filename=filename, _external=True)
        return jsonify({'filename': filename, 'url': file_url})

    return jsonify({'error': 'No file uploaded'}), 400

@app.route('/pastebin/<filename>')
def view_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        return redirect(url_for('img_not_found'))

    pastebin = Pastebin.query.filter_by(id=filename).first()
    if pastebin and pastebin.delete_on_view:
        db.session.delete(pastebin)
        db.session.commit()
        os.remove(file_path)

    return send_file(file_path)

@app.route('/my_pastebins')
@login_required
def my_pastebins():
    pastebins = Pastebin.query.filter_by(user_id=current_user.id).all()
    return render_template('my-pastebins.html', pastebins=pastebins)

@app.route('/delete_pastebin/<filename>', methods=['POST'])
@login_required
def delete_pastebin(filename):
    pastebin = Pastebin.query.filter_by(id=filename, user_id=current_user.id).first()
    if pastebin:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(pastebin)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Pastebin not found or permission denied'})

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
        
        hashed_password = generate_password_hash(password)
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if user.is_active:
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Please confirm your email before logging in.')
        else:
            flash('Invalid credentials')

    return render_template('login.html')

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
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error during OAuth callback: {str(e)}")
        return jsonify({"success": False, "error": f"Error during OAuth callback: {str(e)}"}), 500

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Permission denied'})

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'User not found'})

@app.route('/blocked')
def blocked():
    message = session.pop('popup_message', None)
    return render_template('blocked.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
