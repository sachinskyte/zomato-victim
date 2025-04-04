# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, escape
import sqlite3
import os
import json
from datetime import datetime
import hashlib
import secrets
import re
from functools import wraps

app = Flask(__name__)
# Deliberately weak secret key for session tampering vulnerability
app.secret_key = "zomato_secret_key_123"

# CSRF Protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# Add CSRF token to all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# CSRF protection decorator
def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                return redirect(url_for('dashboard', error='CSRF validation failed'))
        return f(*args, **kwargs)
    return decorated_function

# Admin role required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Database setup
def init_db():
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    # Drop tables to reset data
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS restaurants')
    cursor.execute('DROP TABLE IF EXISTS reviews')
    cursor.execute('DROP TABLE IF EXISTS orders')
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        cuisine TEXT NOT NULL,
        rating FLOAT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        user_id INTEGER,
        comment TEXT NOT NULL,
        rating INTEGER,
        date TEXT NOT NULL,
        FOREIGN KEY (restaurant_id) REFERENCES restaurants (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        restaurant_id INTEGER,
        items TEXT NOT NULL,
        total_price FLOAT,
        status TEXT NOT NULL,
        date TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (restaurant_id) REFERENCES restaurants (id)
    )
    ''')
    
    # Insert sample data - using plaintext passwords instead of hashed for simplicity
    # Admin user
    cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('admin', 'admin123', 'admin@zomato.com', 'admin')")
    
    # Regular users
    cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('user1', 'password123', 'user1@example.com', 'user')")
    cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('user2', 'password456', 'user2@example.com', 'user')")
    
    # Sample restaurants
    cursor.execute("INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('Tasty Bites', '123 Main St', 'Indian', 4.5)")
    cursor.execute("INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('Pizza Paradise', '456 Oak Ave', 'Italian', 4.2)")
    cursor.execute("INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('Sushi Corner', '789 Pine Rd', 'Japanese', 4.7)")
    cursor.execute("INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('Burger Joint', '101 Elm St', 'American', 4.3)")
    cursor.execute("INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('Taco Heaven', '202 Maple Ave', 'Mexican', 4.4)")
    
    # Sample reviews with XSS vulnerability
    cursor.execute("INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (1, 2, 'Great food!', 5, '2025-03-10')")
    cursor.execute("INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (1, 3, 'Nice atmosphere but slow service', 3, '2025-03-11')")
    cursor.execute("INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (2, 2, '<b>Best pizza in town!</b>', 4, '2025-03-12')")
    cursor.execute("INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (3, 3, '<i>Fresh sushi and great service</i>', 5, '2025-03-13')")
    cursor.execute("INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (4, 2, '<script>alert(\"XSS vulnerability!\");</script>', 5, '2025-03-14')")
    
    # Sample orders
    cursor.execute("INSERT INTO orders (user_id, restaurant_id, items, total_price, status, date) VALUES (2, 1, 'Butter Chicken, Naan', 24.99, 'Delivered', '2025-03-10')")
    cursor.execute("INSERT INTO orders (user_id, restaurant_id, items, total_price, status, date) VALUES (3, 2, 'Pepperoni Pizza, Garlic Bread', 18.50, 'Pending', '2025-03-12')")
    cursor.execute("INSERT INTO orders (user_id, restaurant_id, items, total_price, status, date) VALUES (2, 3, 'Sushi Platter, Miso Soup', 32.75, 'Processing', '2025-03-14')")
    cursor.execute("INSERT INTO orders (user_id, restaurant_id, items, total_price, status, date) VALUES (3, 4, 'Double Cheeseburger, Fries, Soda', 15.99, 'Delivered', '2025-03-15')")
    cursor.execute("INSERT INTO orders (user_id, restaurant_id, items, total_price, status, date) VALUES (2, 5, 'Beef Tacos (3), Nachos, Guacamole', 22.50, 'Pending', '2025-03-16')")
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Login route with SQL injection vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query (intentional SQL injection)
        conn = sqlite3.connect('zomato.db')
        cursor = conn.cursor()
        
        # Direct string concatenation - SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user[0]
            session['role'] = user[4]
            
            # Vulnerable cookie setting (no httpOnly flag)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user_auth', f"{username}:{user[0]}", max_age=3600)
            return resp
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('user_auth', '', expires=0)
    return resp

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get restaurants
    cursor.execute("SELECT * FROM restaurants ORDER BY rating DESC")
    restaurants = cursor.fetchall()
    
    # Get recent reviews
    cursor.execute("""
    SELECT r.*, u.username, res.name as restaurant_name 
    FROM reviews r 
    JOIN users u ON r.user_id = u.id 
    JOIN restaurants res ON r.restaurant_id = res.id 
    ORDER BY r.date DESC LIMIT 10
    """)
    reviews = cursor.fetchall()
    
    # Get recent orders
    cursor.execute("""
    SELECT o.*, u.username, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id 
    WHERE o.user_id = ? OR ? = 1
    ORDER BY o.date DESC LIMIT 10
    """, (session['user_id'], 1 if session.get('role') == 'admin' else 0))
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', restaurants=restaurants, reviews=reviews, orders=orders)

# Search functionality with SQL injection vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Vulnerable SQL query - direct string concatenation
    sql = f"SELECT * FROM restaurants WHERE name LIKE '%{query}%' OR cuisine LIKE '%{query}%'"
    cursor.execute(sql)
    
    results = cursor.fetchall()
    conn.close()
    
    return render_template('search_results.html', results=results, query=query)

# Admin routes (insufficient access control)
@app.route('/admin')
def admin_dashboard():
    # Vulnerable: Only checks if logged in, not if admin
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    
    # Get all restaurants
    cursor.execute("SELECT * FROM restaurants")
    restaurants = cursor.fetchall()
    
    # Get all orders
    cursor.execute("""
    SELECT o.*, u.username, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id 
    ORDER BY o.date DESC
    """)
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, restaurants=restaurants, orders=orders)

# Vulnerable XSS endpoint (no CSRF protection)
@app.route('/add_review', methods=['POST'])
def add_review():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    restaurant_id = request.form['restaurant_id']
    comment = request.form['comment']  # Unsanitized input
    rating = request.form['rating']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    # Insert the review with unsanitized comment (XSS vulnerability)
    cursor.execute(
        "INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (?, ?, ?, ?, ?)",
        (restaurant_id, session['user_id'], comment, rating, datetime.now().strftime('%Y-%m-%d'))
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# Restaurant details page with SQL injection vulnerability
@app.route('/restaurant')
def restaurant_detail():
    restaurant_id = request.args.get('id')
    
    if not restaurant_id:
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Vulnerable to SQL injection
    query = f"SELECT * FROM restaurants WHERE id = {restaurant_id}"
    cursor.execute(query)
    restaurant = cursor.fetchone()
    
    if not restaurant:
        return redirect(url_for('dashboard'))
    
    # Get reviews for this restaurant
    cursor.execute("""
    SELECT r.*, u.username 
    FROM reviews r 
    JOIN users u ON r.user_id = u.id 
    WHERE r.restaurant_id = {0}
    ORDER BY r.date DESC
    """.format(restaurant_id))
    reviews = cursor.fetchall()
    
    conn.close()
    
    return render_template('restaurant.html', restaurant=restaurant, reviews=reviews)

# Vulnerable API endpoint (leaking sensitive data)
@app.route('/api/users')
def api_users():
    # No authentication check for sensitive data
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, role FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(users)

# Order processing with CSRF vulnerability
@app.route('/process_order', methods=['POST'])
def process_order():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    order_id = request.form.get('order_id')
    status = request.form.get('status')
    
    if order_id and status:
        conn = sqlite3.connect('zomato.db')
        cursor = conn.cursor()
        
        # Update order status (vulnerable to CSRF)
        cursor.execute(
            "UPDATE orders SET status = ? WHERE id = ?",
            (status, order_id)
        )
        
        conn.commit()
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Add new restaurant (CSRF and SQL injection vulnerability)
@app.route('/add_restaurant', methods=['POST'])
def add_restaurant():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    name = request.form['name']
    address = request.form['address']
    cuisine = request.form['cuisine']
    rating = request.form['rating']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    # Vulnerable to SQL injection
    query = f"INSERT INTO restaurants (name, address, cuisine, rating) VALUES ('{name}', '{address}', '{cuisine}', {rating})"
    cursor.execute(query)
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Command injection vulnerability
@app.route('/ping', methods=['POST'])
def ping_server():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    hostname = request.form.get('hostname', '')
    
    # Command injection vulnerability
    result = os.popen(f"ping -c 1 {hostname}").read()
    
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')