import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
import sqlite3



app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key in production

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Create members table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    # Create achievements table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image_filename TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Hardcoded admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

# Routes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/achievements')
def achievements():
    conn = get_db_connection()
    achievements = conn.execute('SELECT * FROM achievements').fetchall()
    conn.close()
    return render_template('achievements.html', achievements=achievements)

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # For simplicity, just flash a message
        flash('Thank you for contacting us!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        if not name or not email or not password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('signup'))
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO members (name, email, password) VALUES (?, ?, ?)',
                         (name, email, password))
            conn.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        conn = get_db_connection()
        member = conn.execute('SELECT * FROM members WHERE email = ? AND password = ?', (email, password)).fetchone()
        conn.close()
        if member:
            session['member_id'] = member['id']
            session['member_name'] = member['name']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Admin logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin login required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        file = request.files.get('image')
        if not title or not description:
            flash('Title and description are required.', 'danger')
            return redirect(url_for('admin_dashboard'))
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        conn.execute('INSERT INTO achievements (title, description, image_filename) VALUES (?, ?, ?)',
                     (title, description, filename))
        conn.commit()
        flash('Achievement added successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    achievements = conn.execute('SELECT * FROM achievements').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', achievements=achievements)

@app.route('/delete_achievement/<int:achievement_id>', methods=['POST'])
@admin_required
def delete_achievement(achievement_id):
    conn = get_db_connection()
    achievement = conn.execute('SELECT * FROM achievements WHERE id = ?', (achievement_id,)).fetchone()
    if achievement:
        if achievement['image_filename']:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], achievement['image_filename'])
            if os.path.exists(image_path):
                os.remove(image_path)
        conn.execute('DELETE FROM achievements WHERE id = ?', (achievement_id,))
        conn.commit()
        flash('Achievement deleted successfully.', 'success')
    else:
        flash('Achievement not found.', 'danger')
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Access control for member pages
@app.before_request
def restrict_member_pages():
    member_pages = ['index', 'history', 'achievements', 'contact']
    admin_pages = ['admin_dashboard', 'delete_achievement']
    if request.endpoint in member_pages:
        # Allow if member logged in or not (members can view these pages without login)
        pass
    elif request.endpoint in ['login', 'signup', 'admin_login', 'static', 'uploaded_file']:
        # Allow these endpoints without restriction
        pass
    elif request.endpoint in admin_pages:
        # Admin pages require admin login
        if not session.get('admin_logged_in'):
            flash('Admin login required.', 'danger')
            return redirect(url_for('admin_login'))
    else:
        # For other pages, require member login
        if not session.get('member_id'):
            flash('Member login required.', 'danger')
            return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
