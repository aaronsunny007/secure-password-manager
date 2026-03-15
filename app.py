import traceback
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
import os
import mysql.connector
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pyotp
import time
from flask_mail import Mail, Message
from functools import wraps
import secrets
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Session timeout configuration (in seconds)
SESSION_TIMEOUT = 300  # 5 minutes

# Database configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Murali/986",
    database="pwdmngr"
)

# Simulating a simple in-memory storage for OTP (For production use, use a database)
otp_store = {}

# Password reset tokens storage (For production use, use a database)
reset_tokens = {}

# OTP Expiry time (in seconds)
OTP_EXPIRY = 300  # 5 minutes

# Password reset token expiry time (in seconds)
RESET_TOKEN_EXPIRY = 3600  # 1 hour

cursor = db.cursor()

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Adjust as needed
app.config['MAIL_PORT'] = 587  # Adjust as needed
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'murali.nanepalli2003@gmail.com'  # Your email here
app.config['MAIL_PASSWORD'] = 'kuzx jnka plug asuj'  # Your email password here
app.config['MAIL_DEFAULT_SENDER'] = 'lokanadam@gmail.com'

mail = Mail(app)

def check_session_timeout():
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > SESSION_TIMEOUT:
            session.clear()
            return True
    return False

def update_session_activity():
    session['last_activity'] = time.time()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('home'))
        if check_session_timeout():
            flash('Your session has expired. Please login again.')
            return redirect(url_for('home'))
        update_session_activity()
        return f(*args, **kwargs)
    return decorated_function

# Generate a key (only once, and store it securely)
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Load the key from the key file
def load_key():
    if not os.path.exists("key.key"):
        generate_key()
    with open("key.key", "rb") as key_file:
        return key_file.read()

key = load_key()

# Encrypt a password
def encrypt_password(password):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

# Decrypt a password
def decrypt_password(encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

@app.route('/send_otp', methods=['GET', 'POST'])
@login_required
def send_otp():
    print('1')
    user_id = session['user_id']
    print('1')
    # Get email from database
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user_email = cursor.fetchone()
    if user_email:
        email = user_email[0]
    else:
        flash("User email not found.")
        return redirect(url_for('home'))
    print('2')
    otp_key = pyotp.random_base32()
    # Generate OTP and send it to email
    otp = pyotp.TOTP(otp_key)  # You can use a more secure OTP generation here
    otp_code = otp.now()

    otp_store[user_id] = {'otp': otp_code, 'timestamp': time.time()}

    # Send OTP email
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is: {otp_code}'
    print('otp code ', otp_code)
    print('3')
    try:
        mail.send(msg)
        print('4')
        flash('OTP sent to your email.')
        return redirect(url_for('verify_otp'))
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash(f"Error sending email: {str(e)}")
        time.sleep(5)
        return redirect(url_for('send_otp'))

@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    try:
        if request.method == 'POST':
            user_id = session['user_id']
            entered_otp = request.form['otp']

            # Check OTP validity
            otp_details = otp_store.get(user_id)
            if otp_details:
                stored_otp = otp_details['otp']
                timestamp = otp_details['timestamp']
                
                # Check if OTP is expired
                if time.time() - timestamp > OTP_EXPIRY:
                    flash("OTP expired, please request a new one.")
                    del otp_store[user_id]
                    return redirect(url_for('send_otp'))
                
                # Verify OTP
                if entered_otp == stored_otp:
                    flash('Login successful!')
                    update_session_activity()  # Update session activity on successful login
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid OTP. Please try again.')

            return redirect(url_for('verify_otp'))
    except Exception as exp:
        print('oops ', exp, traceback.print_exc)
    return render_template('verify_otp.html')

@app.route('/')
def home():
    if 'user_id' in session:
        if check_session_timeout():
            session.clear()
            return render_template('login.html')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = encrypt_password(request.form['password'])

        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, password))
        db.commit()
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        print('user',user)
        if user and decrypt_password(user[1]) == password:
            session['user_id'] = user[0]
            update_session_activity()  # Set initial session activity time
            return redirect(url_for('send_otp'))
        else:
            return "Invalid credentials"

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user information
        cursor.execute("SELECT username FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            return redirect(url_for('home'))
        
        # Get all password details including id
        cursor.execute("""
            SELECT id, service, username, password 
            FROM passwords 
            WHERE user_id = %s
        """, (session['user_id'],))
        passwords = cursor.fetchall()
        
        # Decrypt passwords and create a list of dictionaries
        decrypted_passwords = []
        for pwd in passwords:
            decrypted_passwords.append({
                'id': pwd[0],
                'service': pwd[1],
                'username': pwd[2],
                'password': decrypt_password(pwd[3])
            })
        
        return render_template('dashboard.html', 
                             passwords=decrypted_passwords,
                             current_user={'username': user[0]})
                             
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        traceback.print_exc()
        flash('Error loading dashboard. Please try again.', 'danger')
        return redirect(url_for('home'))

@app.route('/add', methods=['POST'])
@login_required
def add_password():
    service = request.form['service']
    username = request.form['username']
    password = encrypt_password(request.form['password'])

    cursor.execute("INSERT INTO passwords (user_id, service, username, password) VALUES (%s, %s, %s, %s)",
                   (session['user_id'], service, username, password))
    db.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/extend-session', methods=['POST'])
@login_required
def extend_session():
    update_session_activity()
    return {'success': True}

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if email exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            # Generate reset token
            token = secrets.token_urlsafe(32)
            reset_tokens[token] = {
                'user_id': user[0],
                'timestamp': time.time()
            }
            
            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Send reset email
            msg = Message('Password Reset Request',
                         recipients=[email])
            msg.body = f'''To reset your password, visit the following link:
{reset_link}

If you did not make this request then simply ignore this email.
'''
            try:
                mail.send(msg)
                flash('Password reset instructions have been sent to your email.', 'success')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'danger')
        else:
            flash('Email address not found.', 'danger')
            
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token not in reset_tokens:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('forgot_password'))
        
    token_data = reset_tokens[token]
    if time.time() - token_data['timestamp'] > RESET_TOKEN_EXPIRY:
        del reset_tokens[token]
        flash('Reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
            
        # Update password
        encrypted_password = encrypt_password(password)
        cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                      (encrypted_password, token_data['user_id']))
        db.commit()
        
        # Delete used token
        del reset_tokens[token]
        
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

@app.route('/edit_password', methods=['POST'])
@login_required
def edit_password():
    try:
        id = request.form.get('id')
        service = request.form.get('service')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Encrypt the password
        encrypted_password = encrypt_password(password)
        
        # Update the password in the database
        cursor.execute("""
            UPDATE passwords 
            SET service = %s, username = %s, password = %s 
            WHERE id = %s AND user_id = %s
        """, (service, username, encrypted_password, id, session['user_id']))

        db.commit()
        flash('Password updated successfully!', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error updating password. Please try again.', 'danger')
        print(f"Error updating password: {str(e)}")
        traceback.print_exc()
    
    return redirect(url_for('dashboard'))

@app.route('/delete_password/<int:id>')
@login_required
def delete_password(id):
    try:
        # Delete the password from the database
        cursor.execute("DELETE FROM passwords WHERE id = %s AND user_id = %s", (id, session['user_id']))
        db.commit()
        flash('Password deleted successfully!', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Error deleting password. Please try again.', 'danger')
        print(f"Error deleting password: {str(e)}")
        traceback.print_exc()
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
