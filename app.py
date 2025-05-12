from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import pickle
import xml.etree.ElementTree as ET
from config import Config  # Import the Config class from config.py

app = Flask(__name__)
app.config.from_object(Config)  # Load configurations from the Config class

# Simple database for SQL Injection
def init_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE users (username TEXT, password TEXT)''')
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'testpassword')")
        conn.commit()
        conn.close()

init_db()

# Home page
@app.route('/')
def home():
    return render_template('home.html')

# Login Page with SQL Injection vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable to SQL Injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

# Command Injection Vulnerability
@app.route('/system')
def system_command():
    command = request.args.get('command', '')
    # Vulnerable to command injection
    os.system(command)  # This could execute any shell command
    return "Command Executed"

# XSS Vulnerabilities (Reflected and Stored)
@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    # Reflecting user input without sanitizing it (Stored XSS vulnerability)
    return f"<h1>{comment}</h1>"

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    return f"Search Results for: {query}"  # Vulnerable to reflected XSS

# Insecure Deserialization
@app.route('/load_data', methods=['POST'])
def load_data():
    serialized_data = request.form['data']
    # Vulnerable to insecure deserialization, could be exploited with malicious payloads
    data = pickle.loads(serialized_data)  # Vulnerable to malicious payloads
    return f"Data Loaded: {data}"

# XML External Entity (XXE) Vulnerability
@app.route('/xml_upload', methods=['POST'])
def xml_upload():
    xml_data = request.files['xml'].read()
    tree = ET.ElementTree(ET.fromstring(xml_data))  # Vulnerable to XXE
    return "XML Processed"

# Broken Authentication and Session Management
@app.route('/admin')
def admin():
    if session.get('username') != 'admin':
        return "Unauthorized", 403  # Broken access control
    return render_template('admin.html')

# Sensitive Data Exposure - Hardcoded Passwords
@app.route('/settings')
def settings():
    return "Settings Page - Hardcoded Admin Password: password123"

# Security Misconfiguration - Debugging enabled in production
app.config['DEBUG'] = False  # This should be disabled in production

# CSRF Vulnerability - Cross-Site Request Forgery
@app.route('/update_settings', methods=['POST'])
def update_settings():
    # Vulnerable to CSRF because there's no CSRF token
    new_password = request.form['new_password']
    # Imagine we update a sensitive setting here
    return f"Password Updated to: {new_password}"

# Insufficient Logging and Monitoring
@app.route('/trigger_error')
def trigger_error():
    # This endpoint triggers an error intentionally to simulate insufficient logging and monitoring
    raise Exception("Simulated Error")

# Insecure Direct Object Reference (IDOR) vulnerability
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Vulnerable to IDOR because no access control is enforced
    return f"Displaying profile for user {user_id}"

# Unvalidated Redirects and Forwards
@app.route('/redirect', methods=['GET'])
def unvalidated_redirect():
    target = request.args.get('target')
    if target:
        return redirect(target)  # Vulnerable to unvalidated redirects
    return "No target specified"

# Logout (Sign Out) functionality
@app.route('/logout')
def logout():
    # Remove the user session
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
