# Pastebin App 🗂️

A simple Pastebin application built with Flask. 🚀 It features user authentication, paste creation, and Google OAuth integration. Users can create, view, and manage pastes, with options for expiration and auto-deletion. 🗑️🔒

## Features ✨

- **User Authentication**: Register, log in, and manage your account. 🛡️
- **Paste Management**: Create, view, and delete pastes. 📝
- **Expiration Options**: Set pastes to be deleted on view or after a specified time. ⏳
- **Google OAuth**: Log in using Google account. 🔑
- **Account Management**: Delete your account and all associated pastes. 🧹

## Technologies ⚙️

- **Flask**: Web framework for building the application.
- **Flask-Login**: User session management.
- **Flask-Mail**: Sending email confirmations.
- **Flask-SQLAlchemy**: ORM for database interactions.
- **Flask-Bcrypt**: Password hashing.
- **Flask-Migrate**: Database migrations.
- **Requests-OAuthlib**: OAuth 2.0 support for Google login.

## Setup 🛠️

1. **Clone the repository**:

    ```bash
    git clone https://github.com/yourusername/pastebin-app.git
    cd pastebin-app
    ```

2. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

3. **Create a `.env` file**:

    Copy the `.env.example` file to `.env` and update the values:

    ```env
    SECRET_KEY=your_secret_key
    MAIL_SERVER=smtp.dreamhost.com
    MAIL_PORT=587
    MAIL_USE_TLS=True
    MAIL_USERNAME=noreply@travis-hopkins.com
    MAIL_PASSWORD=your_mail_password
    ```

4. **Initialize the database**:

    ```bash
    flask db upgrade
    ```

5. **Run the application**:

    ```bash
    flask run
    ```

## Usage 🚀

- **Homepage**: Access the application at `http://localhost:5000`.
- **Register**: Sign up for an account.
- **Login**: Log in using your credentials or Google account.
- **Create Paste**: Use the form to create a new paste.
- **View Paste**: Access pastes using their unique URL.
- **Manage Pastes**: View and delete your pastes in the user dashboard.
- **Delete Account**: Permanently delete your account and pastes.

## Contributing 🤝

1. **Fork the repository**.
2. **Create a new branch**:
   
   ```bash
   git checkout -b feature/your-feature
