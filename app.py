# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import sqlite3
import os
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = "very_secret_key_123"  # Weak secret key

# Database setup
def init_db():
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
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
    
    # Insert sample data
    # Admin user (vulnerable to SQL injection)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'admin123', 'admin@zomato.com', 'admin')")
    
    # Regular users
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (2, 'user1', 'password123', 'user1@example.com', 'user')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (3, 'user2', 'password456', 'user2@example.com', 'user')")
    
    # Sample restaurants
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (1, 'Tasty Bites', '123 Main St', 'Indian', 4.5)")
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (2, 'Pizza Paradise', '456 Oak Ave', 'Italian', 4.2)")
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (3, 'Sushi Corner', '789 Pine Rd', 'Japanese', 4.7)")
    
    # Sample reviews with unsanitized content (XSS vulnerability)
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (1, 1, 2, 'Great food!', 5, '2025-03-10')")
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (2, 1, 3, 'Nice atmosphere but slow service', 3, '2025-03-11')")
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (3, 2, 2, '<script>alert(\"XSS vulnerability\")</script>', 4, '2025-03-12')")
    
    # Sample orders
    cursor.execute("INSERT OR IGNORE INTO orders (id, user_id, restaurant_id, items, total_price, status, date) VALUES (1, 2, 1, 'Butter Chicken, Naan', 24.99, 'Delivered', '2025-03-10')")
    cursor.execute("INSERT OR IGNORE INTO orders (id, user_id, restaurant_id, items, total_price, status, date) VALUES (2, 3, 2, 'Pepperoni Pizza, Garlic Bread', 18.50, 'Pending', '2025-03-12')")
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Vulnerable login route (SQL Injection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query (intentional SQL injection)
        conn = sqlite3.connect('zomato.db')
        cursor = conn.cursor()
        
        # Vulnerable query - direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user[0]
            session['role'] = user[4]
            
            # Vulnerable cookie setting (no httpOnly or secure flags)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user_auth', username + ':' + password)  # Storing credentials in plaintext
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
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get restaurants
    cursor.execute("SELECT * FROM restaurants")
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
    ORDER BY o.date DESC LIMIT 10
    """)
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', restaurants=restaurants, reviews=reviews, orders=orders)

# Admin routes (with insufficient access control)
@app.route('/admin')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No proper role checking - any logged-in user can access admin
    # Vulnerable authorization check
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT * FROM users")
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

# Vulnerable XSS endpoint
@app.route('/add_review', methods=['POST'])
def add_review():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF protection
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

# Vulnerable API endpoint (customer data)
@app.route('/api/orders')
def api_orders():
    # No authentication check for sensitive data
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT o.*, u.username, u.email, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id
    """)
    orders = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(orders)

# Vulnerable form submission (CSRF vulnerability)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF token validation
    email = request.form['email']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (email, session['user_id'])
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# Vulnerable order processing (CSRF vulnerability)
@app.route('/process_order', methods=['POST'])
def process_order():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF token validation
    order_id = request.form['order_id']
    status = request.form['status']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (status, order_id)
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=8000)  # Now runs on port 8000
 # Debug mode enabled (security risk)