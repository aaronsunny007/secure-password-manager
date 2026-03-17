import os
import time
import secrets
import traceback
import bcrypt
import mysql.connector

from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Session timeout configuration (in seconds)
SESSION_TIMEOUT = 300  # 5 minutes

# OTP expiry time
OTP_EXPIRY = 300  # 5 minutes

# Password reset token expiry time
RESET_TOKEN_EXPIRY = 3600  # 1 hour

# In-memory stores
# For demo/learning project only. For production, store these in a database or cache.
otp_store = {}
reset_tokens = {}

# Flask-Mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


def check_session_timeout():
    if "last_activity" in session:
        if time.time() - session["last_activity"] > SESSION_TIMEOUT:
            session.clear()
            return True
    return False


def update_session_activity():
    session["last_activity"] = time.time()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))

        if check_session_timeout():
            flash("Your session has expired. Please login again.", "warning")
            return redirect(url_for("home"))

        update_session_activity()
        return f(*args, **kwargs)

    return decorated_function


# ---------- Fernet key handling for stored service passwords ----------

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    if not os.path.exists("key.key"):
        generate_key()
    with open("key.key", "rb") as key_file:
        return key_file.read()


key = load_key()


def encrypt_vault_password(password):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()


def decrypt_vault_password(encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()


# ---------- bcrypt hashing for user account passwords ----------

def hash_user_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_user_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


# ---------- Routes ----------

@app.route("/")
def home():
    if "user_id" in session:
        if check_session_timeout():
            session.clear()
            return render_template("login.html")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        hashed_password = hash_user_password(password)

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Email already registered. Please login.", "warning")
                return redirect(url_for("home"))

            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            db.commit()

            flash("Registration successful. Please login.", "success")
            return redirect(url_for("home"))

        except Exception as e:
            db.rollback()
            print(f"Error in register: {str(e)}")
            traceback.print_exc()
            flash("Registration failed. Please try again.", "danger")
            return redirect(url_for("register"))

        finally:
            cursor.close()
            db.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and check_user_password(password, user[1]):
                session["user_id"] = user[0]
                update_session_activity()
                return redirect(url_for("send_otp"))
            else:
                flash("Invalid credentials.", "danger")
                return redirect(url_for("home"))

        except Exception as e:
            print(f"Error in login: {str(e)}")
            traceback.print_exc()
            flash("Login failed. Please try again.", "danger")
            return redirect(url_for("home"))

        finally:
            cursor.close()
            db.close()

    return render_template("login.html")


@app.route("/send_otp", methods=["GET", "POST"])
@login_required
def send_otp():
    user_id = session["user_id"]

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user_email = cursor.fetchone()

        if not user_email:
            flash("User email not found.", "danger")
            return redirect(url_for("home"))

        email = user_email[0]

        otp_code = str(secrets.randbelow(900000) + 100000)
        otp_store[user_id] = {
            "otp": otp_code,
            "timestamp": time.time()
        }

        msg = Message("Your OTP Code", recipients=[email])
        msg.body = f"Your OTP code is: {otp_code}"

        mail.send(msg)
        flash("OTP sent to your email.", "success")
        return redirect(url_for("verify_otp"))

    except Exception as e:
        print(f"Error sending OTP email: {str(e)}")
        traceback.print_exc()
        flash("Error sending OTP email. Please try again.", "danger")
        return redirect(url_for("home"))

    finally:
        cursor.close()
        db.close()


@app.route("/verify_otp", methods=["GET", "POST"])
@login_required
def verify_otp():
    try:
        if request.method == "POST":
            user_id = session["user_id"]
            entered_otp = request.form["otp"].strip()

            otp_details = otp_store.get(user_id)

            if not otp_details:
                flash("No OTP found. Please request a new OTP.", "warning")
                return redirect(url_for("send_otp"))

            stored_otp = otp_details["otp"]
            timestamp = otp_details["timestamp"]

            if time.time() - timestamp > OTP_EXPIRY:
                del otp_store[user_id]
                flash("OTP expired, please request a new one.", "warning")
                return redirect(url_for("send_otp"))

            if entered_otp == stored_otp:
                del otp_store[user_id]
                update_session_activity()
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid OTP. Please try again.", "danger")
                return redirect(url_for("verify_otp"))

    except Exception as e:
        print(f"Error in verify_otp: {str(e)}")
        traceback.print_exc()
        flash("OTP verification failed.", "danger")

    return render_template("verify_otp.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
        user = cursor.fetchone()

        if not user:
            session.clear()
            return redirect(url_for("home"))

        cursor.execute(
            """
            SELECT id, service, username, password
            FROM passwords
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )
        passwords = cursor.fetchall()

        decrypted_passwords = []
        for pwd in passwords:
            decrypted_passwords.append({
                "id": pwd[0],
                "service": pwd[1],
                "username": pwd[2],
                "password": decrypt_vault_password(pwd[3])
            })

        return render_template(
            "dashboard.html",
            passwords=decrypted_passwords,
            current_user={"username": user[0]}
        )

    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        traceback.print_exc()
        flash("Error loading dashboard. Please try again.", "danger")
        return redirect(url_for("home"))

    finally:
        cursor.close()
        db.close()


@app.route("/add", methods=["POST"])
@login_required
def add_password():
    service = request.form["service"].strip()
    username = request.form["username"].strip()
    password = request.form["password"]

    encrypted_password = encrypt_vault_password(password)

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO passwords (user_id, service, username, password)
            VALUES (%s, %s, %s, %s)
            """,
            (session["user_id"], service, username, encrypted_password)
        )
        db.commit()
        flash("Password added successfully!", "success")

    except Exception as e:
        db.rollback()
        print(f"Error adding password: {str(e)}")
        traceback.print_exc()
        flash("Error adding password. Please try again.", "danger")

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("dashboard"))


@app.route("/edit_password", methods=["POST"])
@login_required
def edit_password():
    db = get_db_connection()
    cursor = db.cursor()

    try:
        password_id = request.form.get("id")
        service = request.form.get("service", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        encrypted_password = encrypt_vault_password(password)

        cursor.execute(
            """
            UPDATE passwords
            SET service = %s, username = %s, password = %s
            WHERE id = %s AND user_id = %s
            """,
            (service, username, encrypted_password, password_id, session["user_id"])
        )

        db.commit()
        flash("Password updated successfully!", "success")

    except Exception as e:
        db.rollback()
        print(f"Error updating password: {str(e)}")
        traceback.print_exc()
        flash("Error updating password. Please try again.", "danger")

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("dashboard"))


@app.route("/delete_password/<int:password_id>")
@login_required
def delete_password(password_id):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute(
            "DELETE FROM passwords WHERE id = %s AND user_id = %s",
            (password_id, session["user_id"])
        )
        db.commit()
        flash("Password deleted successfully!", "success")

    except Exception as e:
        db.rollback()
        print(f"Error deleting password: {str(e)}")
        traceback.print_exc()
        flash("Error deleting password. Please try again.", "danger")

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


@app.route("/extend-session", methods=["POST"])
@login_required
def extend_session():
    update_session_activity()
    return {"success": True}


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip()

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                token = secrets.token_urlsafe(32)
                reset_tokens[token] = {
                    "user_id": user[0],
                    "timestamp": time.time()
                }

                reset_link = url_for("reset_password", token=token, _external=True)

                msg = Message("Password Reset Request", recipients=[email])
                msg.body = f"""To reset your password, visit the following link:

{reset_link}

If you did not make this request, simply ignore this email.
"""
                mail.send(msg)
                flash("Password reset instructions have been sent to your email.", "success")
            else:
                flash("Email address not found.", "danger")

        except Exception as e:
            print(f"Error in forgot_password: {str(e)}")
            traceback.print_exc()
            flash("Error sending reset email. Please try again later.", "danger")

        finally:
            cursor.close()
            db.close()

        return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if token not in reset_tokens:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("forgot_password"))

    token_data = reset_tokens[token]

    if time.time() - token_data["timestamp"] > RESET_TOKEN_EXPIRY:
        del reset_tokens[token]
        flash("Reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        hashed_password = hash_user_password(password)

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute(
                "UPDATE users SET password = %s WHERE id = %s",
                (hashed_password, token_data["user_id"])
            )
            db.commit()

            del reset_tokens[token]

            flash("Your password has been reset successfully.", "success")
            return redirect(url_for("home"))

        except Exception as e:
            db.rollback()
            print(f"Error in reset_password: {str(e)}")
            traceback.print_exc()
            flash("Failed to reset password. Please try again.", "danger")

        finally:
            cursor.close()
            db.close()

    return render_template("reset_password.html", token=token)


if __name__ == "__main__":
    app.run(debug=True)
