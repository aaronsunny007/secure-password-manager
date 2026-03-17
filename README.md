# Secure Password Manager

A web-based password manager built with Python, Flask, and MySQL.  
This project allows users to securely store and manage credentials for different services, with features such as encrypted password storage, OTP-based two-factor authentication, password reset, and session timeout handling.

## Features

- User registration and login
- OTP-based two-factor authentication via email
- Secure storage of service credentials
- Password encryption using Fernet
- Password reset via email token
- Session timeout for inactive users
- Add, edit, view, and delete stored passwords
- Dashboard for managing saved credentials

## Tech Stack

- Python
- Flask
- MySQL
- Flask-Mail
- Cryptography (Fernet)
- PyOTP
- HTML/CSS

## Project Structure

```bash
secure-password-manager/
│── app.py
│── requirements.txt
│── .gitignore
│── LICENSE
│── templates/
│   ├── dashboard.html
│   ├── forgot_password.html
│   ├── login.html
│   ├── register.html
│   ├── reset_password.html
│   ├── verify.html
│   └── verify_otp.html

## Database Setup

This project uses MySQL as the backend database.

To run locally, create a database named `pwdmngr` and run the following SQL:

```sql
CREATE DATABASE pwdmngr;
USE pwdmngr;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    email VARCHAR(100),
    password TEXT
);

CREATE TABLE passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    service VARCHAR(100),
    username VARCHAR(100),
    password TEXT
);

## Tech Stack
- Python (Flask)
- MySQL
- HTML & CSS
- Cryptography (Fernet)
- bcrypt (password hashing)
- Flask-Mail (email service)
