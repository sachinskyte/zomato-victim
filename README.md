**Zomato - Vulnerable Flask Dashboard**

Zomato is a deliberately vulnerable Flask web application designed for ethical hacking and penetration testing. It contains common security flaws such as SQL Injection, XSS, CSRF vulnerabilities, and weak session management.

---

## Step-by-Step Installation & Setup Guide

### Step 1: Install Python & Set Up a Virtual Environment
1. Ensure Python is installed on your system. You can check by running:
   ```bash
   python --version
   ```
2. Create a virtual environment by executing:
   ```bash
   python -m venv venv
   ```
3. Activate the virtual environment:
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     .\env\Scripts\Activate.ps1
     ```

### Step 2: Install Required Dependencies
1. Install Flask using pip:
   ```bash
   pip install flask
   ```
2. Ensure all dependencies are installed properly before proceeding.

### Step 3: Run the Application
1. Start the application by running:
   ```bash
   python app.py
   ```
2. By default, the application will be accessible at:
   ```
   http://127.0.0.1:8000/
   ```

---

## Features & Vulnerabilities
- **Login System**: Vulnerable to **SQL Injection**.
- **User Dashboard**: Allows **XSS (Cross-Site Scripting)** via user reviews.
- **Insecure Cookies**: Sessions stored without `HttpOnly` or `Secure` flags.
- **CSRF Vulnerability**: Forms lack CSRF protection.
- **Admin Panel**: Accessible with hardcoded credentials.

---

## Default Credentials

| Role  | Username | Password |
|--------|---------|-----------|
| Admin  | `admin`  | `admin123` |
| User 1 | `user1`  | `password123` |
| User 2 | `user2`  | `password456` |

---

## How to Use
1. Open your browser and visit:
   ```
   http://127.0.0.1:8000/login
   ```
2. Log in using one of the default credentials.
3. Admin users can access the admin panel at:
   ```
   http://127.0.0.1:8000/admin
   ```
4. Test for **XSS** vulnerabilities by posting reviews in the dashboard.
5. Attempt **SQL Injection** via the login form.

---

## Disclaimer
This project is intended for **educational purposes only**. Do not deploy it on a public server. Use responsibly.
