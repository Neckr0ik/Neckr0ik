#!/usr/bin/env python3
"""
SQL Defence Playground - Vulnerable Application
Author: Giovanni Oliveira
Description: Intentionally vulnerable web application for SQL injection testing
WARNING: This application contains security vulnerabilities for educational purposes only
"""

from flask import Flask, request, render_template, jsonify, session, redirect, url_for
import sqlite3
import hashlib
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerable_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_123'  # Intentionally weak secret

# Database configuration
DATABASE = 'vulnerable_database.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with sample data"""
    conn = get_db_connection()
    
    # Create tables
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    sample_users = [
        ('admin', 'admin123', 'admin@example.com', 'admin'),
        ('john_doe', 'password123', 'john@example.com', 'user'),
        ('jane_smith', 'secret456', 'jane@example.com', 'user'),
        ('test_user', 'test123', 'test@example.com', 'user')
    ]
    
    for username, password, email, role in sample_users:
        # Intentionally weak password hashing
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        try:
            conn.execute(
                'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                (username, hashed_password, email, role)
            )
        except sqlite3.IntegrityError:
            pass  # User already exists
    
    sample_products = [
        ('Laptop', 'High-performance laptop', 999.99, 'Electronics'),
        ('Smartphone', 'Latest smartphone model', 699.99, 'Electronics'),
        ('Book', 'Programming guide', 29.99, 'Books'),
        ('Headphones', 'Wireless headphones', 199.99, 'Electronics'),
        ('Coffee Mug', 'Ceramic coffee mug', 12.99, 'Home')
    ]
    
    for name, description, price, category in sample_products:
        try:
            conn.execute(
                'INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)',
                (name, description, price, category)
            )
        except sqlite3.IntegrityError:
            pass  # Product already exists
    
    conn.commit()
    conn.close()
    logger.info("Database initialized with sample data")

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login functionality - VULNERABLE to SQL injection"""
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Direct string concatenation allows SQL injection
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
    
    logger.info(f"Login attempt - Query: {query}")
    
    conn = get_db_connection()
    
    try:
        cursor = conn.execute(query)
        user = cursor.fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            logger.info(f"Successful login for user: {username}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error='Invalid credentials')
    
    except Exception as e:
        # VULNERABLE: Exposing database errors to users
        logger.error(f"Database error during login: {e}")
        return render_template('login.html', error=f'Database error: {str(e)}')
    
    finally:
        conn.close()

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/search')
def search():
    """Product search - VULNERABLE to SQL injection"""
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    if not query:
        return render_template('search.html', products=[])
    
    conn = get_db_connection()
    
    try:
        # VULNERABLE: Direct string concatenation allows UNION attacks
        if category:
            sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%' AND category = '{category}'"
        else:
            sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        
        logger.info(f"Search query: {sql_query}")
        
        cursor = conn.execute(sql_query)
        products = cursor.fetchall()
        
        return render_template('search.html', products=products, query=query)
    
    except Exception as e:
        # VULNERABLE: Exposing database errors and structure
        logger.error(f"Search error: {e}")
        return render_template('search.html', products=[], error=f'Search error: {str(e)}')
    
    finally:
        conn.close()

@app.route('/user/<user_id>')
def user_profile(user_id):
    """User profile - VULNERABLE to blind SQL injection"""
    conn = get_db_connection()
    
    try:
        # VULNERABLE: Direct parameter insertion
        query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
        
        logger.info(f"Profile query: {query}")
        
        cursor = conn.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            })
        else:
            return jsonify({'error': 'User not found'}), 404
    
    except Exception as e:
        # VULNERABLE: Detailed error information
        logger.error(f"Profile error: {e}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    finally:
        conn.close()

@app.route('/logout')
def logout():
    """Logout functionality"""
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # VULNERABLE: Exposing internal errors
    logger.error(f"Internal error: {error}")
    return f"Internal server error: {str(error)}", 500

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # VULNERABLE: Debug mode enabled, weak configuration
    logger.warning("Starting VULNERABLE application - FOR EDUCATIONAL USE ONLY")
    logger.warning("This application contains intentional security vulnerabilities")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,  # VULNERABLE: Debug mode in production
        threaded=True
    )