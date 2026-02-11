from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import sqlite3
import subprocess
from config import Config
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)

# Initialize database
db = SQLAlchemy(app)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Plain text password (vulnerable!)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<Product {self.name}>'

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(255))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Log {self.action}>'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def log_activity(action, user_id=None):
    """Log user activity - also vulnerable to injection"""
    try:
        log = ActivityLog(
            user_id=user_id,
            action=action,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown')
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass

def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def get_current_user():
    """Get current logged in user"""
    if is_logged_in():
        return User.query.get(session['user_id'])
    return None

# ============================================================================
# ROUTES - HOME & INFO
# ============================================================================

@app.route('/')
def index():
    """Home page with product listing"""
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/about')
def about():
    """About page with system information (information disclosure)"""
    system_info = {
        'python_version': subprocess.check_output(['python3', '--version']).decode(),
        'os_info': subprocess.check_output(['uname', '-a']).decode(),
        'current_user': subprocess.check_output(['whoami']).decode().strip(),
        'working_directory': os.getcwd(),
        'environment': dict(os.environ)  # Huge vulnerability!
    }
    return render_template('about.html', system_info=system_info)

# ============================================================================
# ROUTES - AUTHENTICATION (VULNERABLE)
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page - VULNERABLE TO SQL INJECTION
    Example payload: admin' OR '1'='1' --
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE SQL QUERY - Direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            # Direct database connection for SQL injection demonstration
            conn = sqlite3.connect('instance/vulnerable_app.db')
            cursor = conn.cursor()
            cursor.execute(query)  # VULNERABLE!
            user_data = cursor.fetchone()
            conn.close()
            
            if user_data:
                session['user_id'] = user_data[0]
                session['username'] = user_data[1]
                session['role'] = user_data[4]
                flash(f'Welcome back, {user_data[1]}!', 'success')
                log_activity(f'User {username} logged in')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials!', 'danger')
        except Exception as e:
            # Verbose error message (information disclosure)
            flash(f'Database error: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registration page - Stores passwords in plain text
    """
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')  # No hashing!
        
        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user with plain text password
        new_user = User(username=username, email=email, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        log_activity(f'New user registered: {username}')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'Unknown')
    session.clear()
    flash('You have been logged out.', 'info')
    log_activity(f'User {username} logged out')
    return redirect(url_for('index'))

# ============================================================================
# ROUTES - DASHBOARD & SEARCH (VULNERABLE)
# ============================================================================

@app.route('/dashboard')
def dashboard():
    """User dashboard - requires login"""
    if not is_logged_in():
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    return render_template('dashboard.html', user=user)

@app.route('/search')
def search():
    """
    Product search - VULNERABLE TO SQL INJECTION
    Example: /search?q=laptop' UNION SELECT 1,username,password,4,5 FROM users--
    """
    query = request.args.get('q', '')
    
    if query:
        # VULNERABLE SQL QUERY
        sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
        
        try:
            conn = sqlite3.connect('instance/vulnerable_app.db')
            cursor = conn.cursor()
            cursor.execute(sql)  # VULNERABLE!
            results = cursor.fetchall()
            conn.close()
            
            return render_template('search.html', query=query, results=results)
        except Exception as e:
            flash(f'Search error: {str(e)}', 'danger')
            return render_template('search.html', query=query, results=[])
    
    return render_template('search.html', query='', results=[])

# ============================================================================
# ROUTES - FILE UPLOAD (VULNERABLE)
# ============================================================================

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    File upload - VULNERABLE TO:
    - No file type validation
    - Arbitrary file upload
    - Path traversal
    - Remote code execution via uploaded files
    """
    if not is_logged_in():
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        # Intentionally insecure - using user-provided filename directly
        filename = request.form.get('filename', file.filename)
        
        # No validation on file type or content!
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        flash(f'File uploaded successfully: {filename}', 'success')
        log_activity(f'File uploaded: {filename}', session.get('user_id'))
        
        return redirect(url_for('upload'))
    
    # List uploaded files
    files = []
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        files = os.listdir(app.config['UPLOAD_FOLDER'])
    
    return render_template('upload.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files - vulnerable to path traversal"""
    # No path sanitization - vulnerable to ../../../etc/passwd
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ============================================================================
# ROUTES - COMMAND INJECTION (VULNERABLE)
# ============================================================================

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    """
    Network ping utility - VULNERABLE TO COMMAND INJECTION
    Example payload: 127.0.0.1; cat /etc/passwd
    """
    if not is_logged_in():
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # VULNERABLE - Direct command execution without sanitization
        command = f"ping -c 4 {host}"
        
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10).decode()
        except subprocess.TimeoutExpired:
            result = "Command timed out!"
        except Exception as e:
            result = f"Error: {str(e)}"
        
        log_activity(f'Ping executed: {host}', session.get('user_id'))
    
    return render_template('ping.html', result=result)

@app.route('/dns-lookup', methods=['GET', 'POST'])
def dns_lookup():
    """
    DNS lookup utility - VULNERABLE TO COMMAND INJECTION
    Example payload: google.com && whoami
    """
    if not is_logged_in():
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        domain = request.form.get('domain', '')
        
        # VULNERABLE - Another command injection vector
        command = f"nslookup {domain}"
        
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10).decode()
        except Exception as e:
            result = f"Error: {str(e)}"
        
        log_activity(f'DNS lookup: {domain}', session.get('user_id'))
    
    return render_template('dns_lookup.html', result=result)

# ============================================================================
# ROUTES - ADMIN PANEL (VULNERABLE)
# ============================================================================

@app.route('/admin')
def admin():
    """
    Admin panel - Weak access control
    Only checks if role is 'admin' in session (can be manipulated)
    """
    if not is_logged_in():
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    # Weak check - session can be manipulated
    if session.get('role') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    
    return render_template('admin.html', users=users, logs=logs)

# ============================================================================
# ROUTES - DEBUG & INFO DISCLOSURE
# ============================================================================

@app.route('/debug')
def debug():
    """Debug page - Massive information disclosure"""
    debug_info = {
        'session': dict(session),
        'cookies': dict(request.cookies),
        'headers': dict(request.headers),
        'environment': dict(os.environ),
        'config': {k: str(v) for k, v in app.config.items()},
        'database_uri': app.config['SQLALCHEMY_DATABASE_URI'],
        'secret_key': app.config['SECRET_KEY'],
    }
    return render_template('debug.html', debug_info=debug_info)

@app.route('/phpinfo')
def phpinfo():
    """Fake phpinfo - shows Python/Flask info instead"""
    info = {
        'Python Version': subprocess.check_output(['python3', '--version']).decode(),
        'Flask Version': '2.3.0',
        'Server': request.environ.get('SERVER_SOFTWARE', 'Unknown'),
        'Document Root': os.getcwd(),
        'Server Admin': 'admin@vulnerable-app.local',
    }
    return render_template('phpinfo.html', info=info)

# ============================================================================
# ERROR HANDLERS - Verbose error messages
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    # Verbose error message (information disclosure)
    return render_template('500.html', error=str(e)), 500

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if already initialized
        if User.query.count() > 0:
            print("Database already initialized!")
            return
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@vulnerable-app.local',
            password='admin123',  # Plain text!
            role='admin'
        )
        db.session.add(admin)
        
        # Create regular users
        users = [
            User(username='john', email='john@example.com', password='password123', role='user'),
            User(username='alice', email='alice@example.com', password='alice2023', role='user'),
            User(username='bob', email='bob@example.com', password='qwerty', role='user'),
        ]
        db.session.add_all(users)
        
        # Create sample products
        products = [
            Product(name='Laptop', description='High performance laptop', price=999.99, stock=10),
            Product(name='Smartphone', description='Latest model smartphone', price=699.99, stock=25),
            Product(name='Headphones', description='Noise cancelling headphones', price=199.99, stock=50),
            Product(name='Tablet', description='10-inch tablet', price=399.99, stock=15),
            Product(name='Smartwatch', description='Fitness tracking smartwatch', price=299.99, stock=30),
        ]
        db.session.add_all(products)
        
        db.session.commit()
        print("Database initialized successfully!")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
