from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import secrets
import string
import hashlib
import json
import os
from datetime import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Use environment variable for secret key in production, generate random one for development
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Security configuration for production
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600  # 1 hour session timeout
)

# Database setup
def setup_database():
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    
    # Users table for authentication and user management
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # User credentials table - now properly linked to users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_name TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email_alias TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Remove old user_settings table if it exists and migrate data if needed
    cursor.execute('DROP TABLE IF EXISTS user_settings')
    
    # Create indexes for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON user_credentials(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_credentials_site_name ON user_credentials(site_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    
    conn.commit()
    conn.close()

def generate_random_string(length=8):
    """Generate random string for email aliases"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def create_email_alias(user_email):
    """Create email alias using + notation"""
    if not user_email or '@' not in user_email:
        return None
    
    username_part, domain_part = user_email.split('@', 1)
    random_suffix = generate_random_string(6)
    return f"{username_part}+{random_suffix}@{domain_part}"

def generate_secure_password(length=16):
    """Generate secure password with mixed characters"""
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one of each type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    
    # Fill the rest randomly
    all_chars = lowercase + uppercase + digits + symbols
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle the password
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

def encrypt_password(password, master_pwd):
    """Simple encryption using master password"""
    # For demo purposes, we'll store the password directly
    # In production, use proper encryption like AES
    return password

def decrypt_password(encrypted_data, master_pwd):
    """Simple decryption - in real app use proper encryption"""
    # For demo purposes, return the stored password
    return encrypted_data

# User authentication helper functions
def get_user_by_email(email):
    """Get user by email"""
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash, full_name, created_at, last_login FROM users WHERE email = ? AND is_active = 1', (email,))
    result = cursor.fetchone()
    conn.close()
    return result

def create_user(email, password, full_name=None):
    """Create a new user"""
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (email, password_hash, full_name)
            VALUES (?, ?, ?)
        ''', (email, generate_password_hash(password), full_name))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def update_last_login(user_id):
    """Update user's last login timestamp"""
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def require_login(f):
    """Decorator to require user login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'user_email' not in session:
            return redirect(url_for('user_login_page'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def home_page():
    """Main landing page"""
    if 'user_id' not in session:
        return redirect(url_for('user_login_page'))
    return render_template('dashboard.html')

@app.route('/register')
def register_page():
    """User registration page"""
    if 'user_id' in session:
        return redirect(url_for('home_page'))
    return render_template('register.html')

@app.route('/login')
def user_login_page():
    """User login page"""
    if 'user_id' in session:
        return redirect(url_for('home_page'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register_user():
    """Handle user registration"""
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    full_name = request.form.get('full_name', '').strip()
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'})
    
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})
    
    # Check if user already exists
    if get_user_by_email(email):
        return jsonify({'success': False, 'message': 'An account with this email already exists'})
    
    # Create new user
    user_id = create_user(email, password, full_name)
    if not user_id:
        return jsonify({'success': False, 'message': 'Failed to create account'})
    
    # Log in the new user
    session['user_id'] = user_id
    session['user_email'] = email
    session['user_name'] = full_name
    update_last_login(user_id)
    
    return jsonify({'success': True, 'redirect': url_for('home_page')})

@app.route('/login', methods=['POST'])
def authenticate_user():
    """Handle user login"""
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'})
    
    user = get_user_by_email(email)
    if not user or not check_password_hash(user[2], password):
        return jsonify({'success': False, 'message': 'Invalid email or password'})
    
    # Log in the user
    session['user_id'] = user[0]
    session['user_email'] = user[1]
    session['user_name'] = user[3]
    update_last_login(user[0])
    
    return jsonify({'success': True, 'redirect': url_for('home_page')})

@app.route('/logout')
def user_logout():
    """Handle user logout"""
    session.clear()
    return redirect(url_for('user_login_page'))

@app.route('/generate_credentials', methods=['POST'])
@require_login
def create_new_credentials():
    """Generate new credentials with email alias"""
    site_name = request.form.get('site_name', '').strip()
    if not site_name:
        return jsonify({'success': False, 'message': 'Site name required'})
    
    # Generate credentials
    user_email = session.get('user_email')
    user_id = session.get('user_id')
    email_alias = create_email_alias(user_email)
    new_password = generate_secure_password()
    
    # Store in database
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO user_credentials (user_id, site_name, username, password_hash, email_alias)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, site_name, email_alias, new_password, email_alias))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'credentials': {
            'site_name': site_name,
            'email': email_alias,
            'password': new_password
        }
    })

@app.route('/get_credentials')
@require_login
def fetch_user_credentials():
    """Get all user credentials"""
    user_id = session.get('user_id')
    
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, site_name, username, password_hash, email_alias, created_at
        FROM user_credentials 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    
    credentials = []
    for row in cursor.fetchall():
        credentials.append({
            'id': row[0],
            'site_name': row[1],
            'username': row[2],
            'password_hash': row[3],
            'email_alias': row[4],
            'created_at': row[5]
        })
    
    conn.close()
    return jsonify({'success': True, 'credentials': credentials})

@app.route('/delete_credential', methods=['POST'])
@require_login
def remove_credential():
    """Delete a credential"""
    credential_id = request.form.get('id')
    if not credential_id:
        return jsonify({'success': False, 'message': 'Credential ID required'})
    
    user_id = session.get('user_id')
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_credentials WHERE id = ? AND user_id = ?', 
                  (credential_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/search_credentials')
@require_login
def search_user_credentials():
    """Search credentials by site name"""
    search_term = request.args.get('q', '').strip()
    if not search_term:
        return fetch_user_credentials()
    
    user_id = session.get('user_id')
    conn = sqlite3.connect('vault_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, site_name, username, password_hash, email_alias, created_at
        FROM user_credentials 
        WHERE user_id = ? AND site_name LIKE ?
        ORDER BY created_at DESC
    ''', (user_id, f'%{search_term}%'))
    
    credentials = []
    for row in cursor.fetchall():
        credentials.append({
            'id': row[0],
            'site_name': row[1],
            'username': row[2],
            'password_hash': row[3],
            'email_alias': row[4],
            'created_at': row[5]
        })
    
    conn.close()
    return jsonify({'success': True, 'credentials': credentials})

if __name__ == '__main__':
    setup_database()
    app.run(debug=True, host='0.0.0.0', port=5001) 