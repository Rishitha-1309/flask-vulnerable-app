import os

class Config:
    # Secret key for sessions (should be kept secret in production)
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')  # Strong secret key should be set in environment

    # Enable/disable debug mode
    DEBUG = False  # Disable debug mode in production

    # Database configuration (example: using PostgreSQL, MySQL, etc.)
    DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')  # Production DB should be set here

    # Optional: Enable production settings like security headers
    SECURITY_HEADERS = True
