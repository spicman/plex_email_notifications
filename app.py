# plex_email_notifications/app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from config import Config
import smtplib
from email.mime.text import MIMEText
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import uuid  # For generating unique tokens
from datetime import datetime, timedelta  # For token expiration
import bleach  # Import bleach
from functools import wraps
import re # ADDED THIS LINE

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Flask-Bcrypt
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to redirect if login is required
login_manager.login_message_category = 'info'

# Database Setup
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,  -- 0 for regular user, 1 for admin
            is_active INTEGER DEFAULT 0, -- 0 for inactive, 1 for active
            activation_token TEXT,
            reset_token TEXT,
            reset_token_expiration DATETIME,
            subscribed_to_notifications INTEGER DEFAULT 1 -- 1 for subscribed, 0 for unsubscribed
        )
    ''')

    # Add this part
    cursor.execute("SELECT id FROM users WHERE subscribed_to_notifications IS NULL")
    users_to_update = cursor.fetchall()

    for user in users_to_update:
        cursor.execute("UPDATE users SET subscribed_to_notifications = 1 WHERE id = ?", (user['id'],))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notification_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            enabled INTEGER DEFAULT 1 -- 1 for enabled, 0 for disabled
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_host TEXT NOT NULL,
            email_port TEXT NOT NULL,
            email_user TEXT NOT NULL,
            email_password TEXT
        )
    ''')

    # Check if settings exist; if not, create defaults from .env
    cursor.execute("SELECT COUNT(*) FROM email_settings")
    settings_count = cursor.fetchone()[0]

    if settings_count == 0:
        email_host = os.environ.get('EMAIL_HOST')
        email_port = os.environ.get('EMAIL_PORT', 587)  # Default to 587
        email_user = os.environ.get('EMAIL_USER')
        email_password = os.environ.get('EMAIL_PASSWORD')
        if email_host is None or email_user is None:
            email_host = 'smtp.gmail.com'
            email_user = "your_email@gmail.com"
        cursor.execute(
            "INSERT INTO email_settings (email_host, email_port, email_user, email_password) VALUES (?, ?, ?, ?)",
            (email_host, email_port, email_user, email_password),
        )
        conn.commit()  # Commit the initial settings

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_to TEXT NOT NULL,  -- Comma-separated list of email addresses
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            template_id INTEGER
        );
    ''')

    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# User class (for Flask-Login)
class User(UserMixin):
    def __init__(self, id, email, password, is_admin, is_active, subscribed_to_notifications):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self._is_active = is_active  # Use a private attribute
        self.subscribed_to_notifications = subscribed_to_notifications

    @property
    def is_active(self):
        return self._is_active

    @is_active.setter
    def is_active(self, value):
        self._is_active = value


    def is_admin_user(self):
        return bool(self.is_admin)

    def is_active_user(self):
        return bool(self.is_active) #This must be implemented in order for the account to login# User loader callback (for Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data and user_data['is_active'] == 1:
        subscribed_to_notifications = user_data['subscribed_to_notifications'] if 'subscribed_to_notifications' in user_data.keys() else 1  # Default to 1 if not found
        return User(id=user_data['id'], email=user_data['email'], password=user_data['password'], is_admin=user_data['is_admin'], is_active=user_data['is_active'], subscribed_to_notifications = subscribed_to_notifications)
    return None

def get_email_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_settings LIMIT 1")
    settings_data = cursor.fetchone()
    conn.close()

    if settings_data:
        return {
            'email_host': settings_data['email_host'],
            'email_port': settings_data['email_port'],
            'email_user': settings_data['email_user'],
            'email_password': settings_data['email_password']
        }
    else:
        return None

# Email Sending Function
def send_email(recipient, subject, message, template_id, settings = None):
    try:
        # Fetch the image URL from the environment variable
        image_url = os.environ.get('EMAIL_HEADER_IMAGE_URL')

        # Load the email header template and pass the image URL
        header_template = render_template('email_header.html', image_url=image_url)

        # Wrap the message body in a styled container
        styled_message = f"""
        <div style="
            background-color: #a1a1a1; /* Light background */
            color: #333; /* Dark text */
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px; /* Space between message and footer (if any) */
            font-family: sans-serif; /* Consistent font */
            line-height: 1.6; /* Improved readability */
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); /* Subtle shadow */
        ">
            {message}
        </div>
        """

        # Combine the header and styled message
        full_message = header_template + styled_message

        msg = MIMEText(full_message, 'html')  # Send as HTML
        msg['Subject'] = subject
        email_settings = settings or get_email_settings()

        msg['From'] = email_settings['email_user'] if email_settings else app.config['EMAIL_USER']
        msg['To'] = recipient

        with smtplib.SMTP(email_settings['email_host'] if email_settings else app.config['EMAIL_HOST'], int(email_settings['email_port']) if email_settings else app.config['EMAIL_PORT']) as server:
            server.starttls()  # Upgrade to secure connection
            server.login(email_settings['email_user'] if email_settings else app.config['EMAIL_USER'], email_settings['email_password'] if email_settings else app.config['EMAIL_PASSWORD'])
            server.sendmail(email_settings['email_user'] if email_settings else app.config['EMAIL_USER'], recipient, msg.as_string())
        print(f"Email sent successfully to {recipient}")

    except Exception as e:
        print(f"Error sending email to {recipient}: {e}")

@app.route('/')
def index():
    if current_user.is_authenticated and current_user.is_admin_user():
        email_settings = get_email_settings()
        if not email_settings or not email_settings['email_host'] or not email_settings['email_user'] or not email_settings['email_password']:
            flash('Please configure the Email Settings to enable user registration and notification features.', 'warning')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # (Input validation - same as before) ...

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate a unique activation token
        activation_token = str(uuid.uuid4())

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if it's the first user (make them admin)
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            is_admin = 1 if user_count == 0 else 0

            cursor.execute("INSERT INTO users (first_name, last_name, email, password, is_admin, activation_token) VALUES (?, ?, ?, ?, ?, ?)", (first_name, last_name, email, hashed_password, is_admin, activation_token))
            conn.commit()
            conn.close()

            # *** MODIFIED SECTION ***
            if is_admin:
                # First user is admin, activate immediately
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET is_active = 1, activation_token = NULL WHERE email = ?", (email,))
                conn.commit()
                conn.close()
                flash('Admin account created and activated! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                # Send activation email (as before)
                activation_link = url_for('activate', token=activation_token, _external=True)
                subject = "Activate Your Account"
                message = f"""
                <p>Dear {first_name} {last_name},</p>
                <p>Thank you for registering!  Please click the link below to activate your account:</p>
                <p><a href="{activation_link}">{activation_link}</a></p>
                """

                # Add a check to make sure email settings exist
                email_settings = get_email_settings()
                if email_settings and email_settings['email_host'] and email_settings['email_user'] and email_settings['email_password']:
                    send_email(email, subject, message, email_settings)
                    flash('Registration successful!  Please check your email to activate your account.', 'info')
                else:
                     flash('Registration successful, but activation email could not be sent because email settings are not configured. Contact an admin.', 'warning')

                return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Email address already registered.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/activate/<token>')
def activate(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE activation_token = ?", (token,))
    user_data = cursor.fetchone()
    print(user_data)
    if user_data:
        cursor.execute("UPDATE users SET is_active = 1, activation_token = NULL WHERE id = ?", (user_data['id'],))
        conn.commit()
        conn.close()
        flash('Account activated successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    else:
        conn.close()
        flash('Invalid activation token.', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User(id=user_data['id'], email=user_data['email'], password=user_data['password'], is_admin=user_data['is_admin'], is_active=user_data['is_active'], subscribed_to_notifications=user_data['subscribed_to_notifications'])

            #Only allows the user to login if the account is active
            if user.is_active_user():
                if bcrypt.check_password_hash(user.password, password):
                    login_user(user)
                    flash('Logged in successfully!', 'success')  # Flash message
                    return redirect(url_for('index'))
                else:
                    flash('Login failed. Incorrect password.', 'error')  # Flash message
                    return render_template('login.html')
            else:
                flash('Account is not active. Please check your email to activate', 'error')
                return render_template('login.html')
        else:
            flash('Login failed.  Incorrect email', 'error')  # Flash message
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info') # Flash message
    return redirect(url_for('index'))

@app.route('/notifications')
@login_required
def notifications():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))
    return render_template('notifications.html')

@app.route('/template_notifications')
@login_required
def template_notifications():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notification_templates")
    templates = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template('template_notifications.html', templates=templates)

@app.route('/template/create', methods=['GET', 'POST'])
@login_required
def create_template():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']

        # Sanitize the HTML before saving
        allowed_tags = list(bleach.ALLOWED_TAGS) + ['p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'u', 'span']  # Add 'span'
        allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'span': ['class'], 'li': ['data-list']}  # Allow class on span
        sanitized_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO notification_templates (subject, message) VALUES (?, ?)", (subject, sanitized_message)) # Store the sanitized version
        conn.commit()
        conn.close()

        flash('Template created successfully!', 'success')
        return redirect(url_for('template_notifications'))

    return render_template('edit_template.html', template=None)  # Pass template=None

@app.route('/template/delete/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notification_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()

    flash('Template deleted successfully!', 'success')
    return redirect(url_for('template_notifications'))

app.route('/template/delete/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notification_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()

    flash('Template deleted successfully!', 'success')
    return redirect(url_for('template_notifications'))

@app.route('/template/<int:template_id>', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notification_templates WHERE id = ?", (template_id,))
    template = cursor.fetchone()

    if not template:
        flash('Template not found.', 'error')
        conn.close()
        return redirect(url_for('template_notifications'))

    template = dict(template) # Convert Row object to dictionary

    preview_content = None # Initialize preview_content here

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update' or not action: #Default action is Update
            subject = request.form['subject']
            message = request.form['message']

            # Sanitize the HTML before saving
            allowed_tags = list(bleach.ALLOWED_TAGS) + ['p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'u', 'ol', 'ul', 'li'] # Add list tags
            allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'span': ['class'], 'li': ['data-list']}
            sanitized_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attributes, strip=True)


            cursor.execute("UPDATE notification_templates SET subject = ?, message = ? WHERE id = ?", (subject, sanitized_message, template_id)) # store the sanitized message
            conn.commit()
            flash('Template updated successfully!', 'success')
        elif action == 'send':
            # Send notification logic
            subject = request.form['subject']
            message = request.form['message']
            email_settings = get_email_settings()

            # Collect recipient emails for history logging
            recipients = []

            cursor.execute("SELECT id, email, subscribed_to_notifications FROM users")
            users = cursor.fetchall()
            for user in users:
                if user['subscribed_to_notifications'] == 1:
                    send_email(user['email'], subject, message, template_id, email_settings)
                    recipients.append(user['email'])

            # Log the notification history with comma-separated recipients
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO notification_history (subject, message, sent_to, template_id) VALUES (?, ?, ?, ?)",
                (subject, message, ', '.join(recipients), template_id)
            )
            conn.commit()
            conn.close()

            flash('Notification sent successfully!', 'success')

        elif action == 'delete':
            cursor.execute("DELETE FROM notification_templates WHERE id = ?", (template_id,))
            conn.commit()
            flash('Template deleted successfully!', 'success')
            return redirect(url_for('template_notifications'))
        elif action == 'preview':
            subject = request.form['subject']
            message = request.form['message']

            # Sanitize the HTML
            allowed_tags = list(bleach.ALLOWED_TAGS) + ['p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'u', 'ol', 'ul', 'li'] #Add list tags
            allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'span': ['class'], 'li': ['data-list']}
            preview_content = bleach.clean(message, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        elif action == 'test':
            subject = request.form['subject']
            message = request.form['message']
            email_settings = get_email_settings()

            # Sanitize the HTML before sending the test email
            allowed_tags = list(bleach.ALLOWED_TAGS) + ['p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'u', 'ol', 'ul', 'li'] #Add list tags
            allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'span': ['class'], 'li': ['data-list']}
            sanitized_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attributes, strip=True)

            send_email(current_user.email, subject, sanitized_message, email_settings)  # Send to current user (using the sanitized version)
            flash('Test notification sent to your email address!', 'success')

        conn.close()
        return redirect(url_for('edit_template', template_id=template_id, preview_content = preview_content))

    conn.close()
    return render_template('edit_template.html', template=template, preview_content = preview_content)

@login_required
def delete_template(template_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notification_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()

    flash('Template deleted successfully!', 'success')
    return redirect(url_for('template_notifications'))

@app.route('/notification_management')
@login_required
def notification_management():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))
    return render_template('notification_management.html')

@app.route('/send_notification', methods=['GET', 'POST'])
@login_required
def send_notification():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, subscribed_to_notifications FROM users")
        users = cursor.fetchall() #get all user details
        conn.close()

        email_settings = get_email_settings()

        # Collect recipient emails for history logging
        recipients = []
        for user in users:
            #Verify notification option before sending email.
            if user['subscribed_to_notifications'] == 1:
                send_email(user['email'], subject, message, 1, email_settings)
                recipients.append(user['email'])

        # Log the notification history with comma-separated recipients
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notification_history (subject, message, sent_to, template_id) VALUES (?, ?, ?, ?)",
            (subject, message, ', '.join(recipients), 1)
        )
        conn.commit()
        conn.close()

        return render_template('success.html', message="Notifications sent successfully!")
    return render_template('send_notification.html')

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        email = request.form['email']
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            #Check if the email already exists
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user_data = cursor.fetchone()

            if user_data:
                #Email exists so update
                cursor.execute("UPDATE users SET subscribed_to_notifications = 1 WHERE id = ?", (user_data['id'],))
            else:
                #Since the email doesn't exist then create the entry
                cursor.execute("INSERT INTO users (email) VALUES (?)", (email,))

            conn.commit()
            conn.close()
            return render_template('success.html', message=f"Successfully subscribed {email}!")
        except sqlite3.IntegrityError:
            return render_template('error.html', message=f"{email} is already subscribed.")
    return render_template('subscribe.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            # Generate reset token and expiration
            reset_token = str(uuid.uuid4())
            expiration = datetime.utcnow() + timedelta(hours=1) # Token valid for 1 hour

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE id = ?", (reset_token, expiration, user_data['id']))
            conn.commit()
            conn.close()

            # Send reset email
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            subject = "Password Reset Request"
            message = f"""
            <p>You have requested a password reset. Please click the link below to reset your password:</p>
            <p><a href="{reset_link}">{reset_link}</a></p>
            <p>This link is valid for one hour.</p>
            """
            email_settings = get_email_settings()
            send_email(email, subject, message, email_settings)

            flash('A password reset link has been sent to your email address.', 'info')
            return redirect(url_for('login'))
        else:
            flash('There is no account registered with this email address.', 'error')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > ?", (token, datetime.utcnow()))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate Input
        if not password or not confirm_password:
            flash('Password cannot be left blank.', 'error')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash("Passwords don't match.", 'error')
            return render_template('reset_password.html', token=token)

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            return render_template('reset_password.html', token=token)

        # Very basic password strength check (can be improved)
        if not (any(char.isdigit() for char in password) and any(char.isalpha() for char in password)):
            flash("Password must contain at least one letter and one number.", 'error')
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE id = ?", (hashed_password, user_data['id']))
        conn.commit()
        conn.close()

        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/options', methods=['GET', 'POST'])
@login_required
def options():
    if request.method == 'POST':
        new_email = request.form.get('email')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        subscribed_to_notifications = request.form.get('notifications') == 'on' # True if 'on', False otherwise

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update email if provided and different
        if new_email and new_email != current_user.email:
            try:
                #Add validation to the email
                if not validate_email(new_email):
                    flash('Invalid email address.', 'error')
                    conn.close()
                    return redirect(url_for('options'))

                cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, current_user.id))
                conn.commit()
                flash('Email address updated successfully!', 'success')
            except sqlite3.IntegrityError:
                flash('This email address is already registered.', 'error')
                conn.close()
                return redirect(url_for('options'))

        # Update password if provided and valid
        if new_password:
            if not confirm_password:
                flash('Please confirm your new password.', 'error')
                conn.close()
                return redirect(url_for('options'))

            if new_password != confirm_password:
                flash("Passwords don't match.", 'error')
                conn.close()
                return redirect(url_for('options'))

            if len(new_password) < 8:
                flash("Password must be at least 8 characters long.", 'error')
                conn.close()
                return redirect(url_for('options'))

            if not (any(char.isdigit() for char in new_password) and any(char.isalpha() for char in new_password)):
                flash("Password must contain at least one letter and one number.", 'error')
                conn.close()
                return redirect(url_for('options'))

            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, current_user.id))
            conn.commit()
            flash('Password updated successfully!', 'success')

        # Update notification subscription
        cursor.execute("UPDATE users SET subscribed_to_notifications = ? WHERE id = ?", (int(subscribed_to_notifications), current_user.id))
        conn.commit()
        flash('Notification settings updated successfully!', 'success')

        conn.close()

        user = load_user(current_user.id)
        login_user(user)

        return redirect(url_for('options'))

    # GET request
    return render_template('options.html', user=current_user)

@login_required
def user_management():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, subscribed_to_notifications FROM users")
    users = []
    rows = cursor.fetchall()
    for row in rows:
        user = {
            'id': row['id'],
            'email': row['email'],
            'subscribed_to_notifications': row['subscribed_to_notifications']
        }
        users.append(user)

    conn.close()

    return render_template('user_management.html', users=users)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data and user_data['is_active'] == 1:
        subscribed_to_notifications = user_data['subscribed_to_notifications'] if 'subscribed_to_notifications' in user_data.keys() else 1  # Default to 1 if not found
        user = User(id=user_data['id'], email=user_data['email'], password=user_data['password'], is_admin=user_data['is_admin'], is_active=user_data['is_active'], subscribed_to_notifications = subscribed_to_notifications)
        user.first_name = user_data['first_name']
        user.last_name = user_data['last_name']
        return user
    return None

@app.route('/user_management')
@login_required
def user_management():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, subscribed_to_notifications FROM users")
    users = []
    rows = cursor.fetchall()
    for row in rows:
        user = {
            'id': row['id'],
            'email': row['email'],
            'subscribed_to_notifications': row['subscribed_to_notifications']
        }
        users.append(user)

    conn.close()

    return render_template('user_management.html', users=users)

@app.route('/toggle_notification/<int:user_id>', methods=['POST'])
@login_required
def toggle_notification(user_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT subscribed_to_notifications FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        new_status = 0 if user_data['subscribed_to_notifications'] == 1 else 1
        cursor.execute("UPDATE users SET subscribed_to_notifications = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        flash('User notification status updated successfully!', 'success')
    else:
        flash('User not found.', 'error')

    conn.close()
    return redirect(url_for('user_management'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        flash("You cannot delete your own account.", 'error')
        return redirect(url_for('user_management'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Error deleting user: {e}", 'error')
    finally:
        conn.close()

    return redirect(url_for('user_management'))

@app.route('/email_settings', methods=['GET', 'POST'])
@login_required
def email_settings():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_settings LIMIT 1")  # Get the single row
    settings_data = cursor.fetchone()

    if not settings_data:
        flash('Email settings not found.', 'error')
        conn.close()
        return redirect(url_for('notification_management'))

    settings = {
        'email_host': settings_data['email_host'],
        'email_port': settings_data['email_port'],
        'email_user': settings_data['email_user'],
        'email_password': settings_data['email_password']
    }

    if request.method == 'POST':
        email_host = request.form['email_host']
        email_port = request.form['email_port']
        email_user = request.form['email_user']
        email_password = request.form['email_password'] # Allow empty password for no change

        cursor.execute(
            "UPDATE email_settings SET email_host=?, email_port=?, email_user=?, email_password=? WHERE id=1",
            (email_host, email_port, email_user, email_password)
        )
        conn.commit()
        flash('Email settings updated successfully!', 'success')
        settings['email_host'] = email_host #Update the settings for the email sending as well
        settings['email_port'] = email_port
        settings['email_user'] = email_user
        settings['email_password'] = email_password

    conn.close()
    return render_template('email_settings.html', settings=settings)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (current_user.id,))
        conn.commit()
        flash('Account deleted successfully!', 'success')
        logout_user() # Log the user out after deleting the account
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Error deleting account: {e}", 'error')
    finally:
        conn.close()

    return redirect(url_for('index'))

# Add these new routes to your app.py
@app.route('/delete_notification/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM notification_history WHERE id = ?", (notification_id,))
        conn.commit()
        flash('Notification deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Error deleting notification: {e}", 'error')
    finally:
        conn.close()

    return redirect(url_for('notification_history'))

@app.route('/delete_all_notifications', methods=['POST'])
@login_required
def delete_all_notifications():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM notification_history")
        conn.commit()
        flash('All notification history entries deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Error deleting all notifications: {e}", 'error')
    finally:
        conn.close()

    return redirect(url_for('notification_history'))

#And make sure the function is in app.route('/notification_history')
@app.route('/notification_history')
@login_required
def notification_history():
    if not current_user.is_admin_user():
        flash("You don't have permission to access this page.", 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notification_history ORDER BY sent_at DESC")
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template('notification_history.html', history=history)

def validate_email(email):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')