from flask import Flask, redirect, request, url_for, flash
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from functools import wraps
from datetime import datetime

# Initialize login manager
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

def get_db_connection():
    """Create and return a database connection."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(id=user['id'], 
                   username=user['username'],
                   email=user['email'],
                   password_hash=user['password_hash'],
                   is_admin=user['is_admin'])
    return None

def init_db():
    """Initialize database with users and access_logs tables"""
    conn = get_db_connection()
    try:
        # Create users table if not exists
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create access_logs table if not exists
        conn.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                ip_address TEXT,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_user ON access_logs(user_id)')
        
        # Check if admin exists
        admin_exists = conn.execute(
            'SELECT 1 FROM users WHERE username = "admin"'
        ).fetchone()
        
        if not admin_exists:
            admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123'))
            conn.execute(
                'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
                ('admin', 'admin@example.com', admin_password, True)
            )
        
        conn.commit()
    finally:
        conn.close()

def log_access(user_id=None, ip_address=None, endpoint=None, method=None, status_code=None):
    """Log user access to the database"""
    conn = get_db_connection()
    try:
        conn.execute(
            '''
            INSERT INTO access_logs 
                (user_id, ip_address, endpoint, method, status_code)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (user_id, ip_address, endpoint, method, status_code)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging access: {e}")
    finally:
        conn.close()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Log admin access
        log_access(
            user_id=current_user.id,
            ip_address=request.remote_addr,
            endpoint=request.path,
            method=request.method,
            status_code=200
        )
        
        return f(*args, **kwargs)
    return decorated_function

# Initialize database when module is imported
init_db()