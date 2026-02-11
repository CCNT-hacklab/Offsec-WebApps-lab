import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """
    Configuration class for the vulnerable web application
    WARNING: This is intentionally insecure for educational purposes
    """
    
    # Flask settings - Intentionally weak
    SECRET_KEY = os.getenv('SECRET_KEY', 'weak_secret_key_12345')
    DEBUG = True  # Intentionally left on for verbose errors
    
    # Database - Using SQLite for simplicity
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///vulnerable_app.db?timeout=30')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True  # Shows SQL queries (information disclosure)
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {'timeout': 30, 'check_same_thread': False}
    }
    
    # File upload settings - Intentionally permissive
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'php', 'sh', 'py'}  # Dangerous!
    
    # Session settings - Intentionally weak
    SESSION_COOKIE_HTTPONLY = False  # Vulnerable to XSS
    SESSION_COOKIE_SECURE = False  # No HTTPS requirement
    PERMANENT_SESSION_LIFETIME = 3600 * 24 * 30  # 30 days
    
    # Admin credentials - Intentionally exposed
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    # Security headers - Intentionally disabled
    SEND_FILE_MAX_AGE_DEFAULT = 0
    
    @staticmethod
    def init_app(app):
        # Create upload folder if it doesn't exist
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
