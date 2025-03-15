# Zomato - Vulnerable Flask Dashboard

Zomato is a deliberately vulnerable Flask web application designed for ethical hacking and penetration testing. This application contains common security flaws such as SQL Injection, XSS, CSRF vulnerabilities, and weak session management.

## Features & Vulnerabilities
- **Login System**: Vulnerable to **SQL Injection**.
- **User Dashboard**: Allows **XSS (Cross-Site Scripting)** via user reviews.
- **Insecure Cookies**: Sessions stored without `HttpOnly` or `Secure` flags.
- **CSRF Vulnerability**: Forms lack CSRF protection.
- **Admin Panel**: Accessible with hardcoded credentials.

---

## Installation & Setup

### 1. Install Python & Virtual Environment
Ensure you have Python installed. Then, set up a virtual environment:

```bash
python -m venv venv  # Create virtual environment
source venv/bin/activate  # Activate on macOS/Linux
venv\Scripts\activate  # Activate on Windows
```

### 2. Install Dependencies

```bash
pip install flask
```

### 3. Run the Application

```bash
python app.py
```

By default, the application runs on `http://127.0.0.1:8000/`.

---

## Default Credentials

| Role  | Username | Password |
|--------|---------|-----------|
| Admin  | `admin`  | `admin123` |
| User 1 | `user1`  | `password123` |
| User 2 | `user2`  | `password456` |

---

## Usage
- Visit `http://127.0.0.1:8000/login` to log in.
- As an **admin**, access `http://127.0.0.1:8000/admin`.
- Post reviews in the dashboard to test **XSS**.
- Attempt **SQL Injection** via the login form.

---

## Disclaimer
This project is for **educational purposes only**. Do not deploy it on a public server. Use responsibly.
