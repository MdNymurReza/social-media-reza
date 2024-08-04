from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import string

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure secret key

DATABASE = 'database.db'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Admin login credentials
ADMIN_CREDENTIALS = {
    'admin_id': 'admin',
    'admin_password': generate_password_hash('admin123')  # Hash the admin password
}

def allowed_file(filename):
    """Check if the file is allowed based on its extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Establish a connection to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_verification_code(length=6):
    """Generate a random verification code."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.route('/')
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        unique_id = request.form['unique_id']
        full_name = request.form['full_name']
        username = request.form['username']
        university = request.form['university']
        email = request.form['email']
        password = request.form['password']
        profile_picture = request.files.get('profile_picture')

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the ID is valid and not registered
        cur.execute("SELECT * FROM ids WHERE unique_id = ? AND is_registered = 0", (unique_id,))
        id_entry = cur.fetchone()

        if id_entry is None:
            flash('Invalid or already registered ID.', 'error')
            return redirect(url_for('register'))

        # Check if the email or username already exists
        cur.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, username))
        user_exists = cur.fetchone()

        if user_exists:
            flash('Email or username already exists.', 'error')
            return redirect(url_for('register'))

        # Handle file upload
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        cur.execute('''
            INSERT INTO users (unique_id, full_name, username, university, email, password, profile_picture)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, full_name, username, university, email, hashed_password, filename))
        
        # Update the ID status to registered
        cur.execute("UPDATE ids SET is_registered = 1 WHERE unique_id = ?", (unique_id,))

        conn.commit()
        conn.close()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if user['is_verified']:
                session['user_id'] = user['id']
                flash('Login successful!', 'success')
                return redirect(url_for('user_dashboard'))
            else:
                flash('Email not verified. Please verify your email.', 'error')
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')

@app.route('/user_dashboard')
def user_dashboard():
    """Render the user dashboard."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    conn.close()

    if user:
        return render_template('dashboard.html', user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('logout'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Allow users to update their profile."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        email = request.form['email']
        university = request.form['university']
        bio = request.form.get('bio', '')
        facebook_link = request.form.get('facebook_link', '')
        twitter_link = request.form.get('twitter_link', '')
        linkedin_link = request.form.get('linkedin_link', '')
        profile_picture = request.files.get('profile_picture')

        cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()

        if user:
            # Handle file upload
            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = user['profile_picture']

            # Update user information
            cur.execute('''
                UPDATE users
                SET email = ?, university = ?, profile_picture = ?, bio = ?, facebook_link = ?, twitter_link = ?, linkedin_link = ?
                WHERE id = ?
            ''', (email, university, filename, bio, facebook_link, twitter_link, linkedin_link, session['user_id']))
            
            conn.commit()

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('logout'))

    # Fetch current user information for display
    cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    conn.close()

    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    """Handle admin login."""
    if request.method == 'POST':
        admin_id = request.form['admin_id']
        admin_password = request.form['admin_password']

        # Check admin credentials
        if (admin_id == ADMIN_CREDENTIALS['admin_id'] and
                check_password_hash(ADMIN_CREDENTIALS['admin_password'], admin_password)):
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))

        flash('Invalid admin credentials.', 'error')

    return render_template('admin.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    """Render the admin dashboard."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_panel'))

    return render_template('admin_dashboard.html')

@app.route('/generate_id', methods=['GET', 'POST'])
def generate_id():
    """Allow admin to generate a new unique ID."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        unique_id = request.form['unique_id']

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO ids (unique_id) VALUES (?)", (unique_id,))
            conn.commit()
            flash('Unique ID generated successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('This ID already exists.', 'error')
        finally:
            conn.close()

    return render_template('generate_id.html')

@app.route('/admin_view_users')
def admin_view_users():
    """Allow admin to view all registered users."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template('admin_view_users.html', users=users)

@app.route('/unregistered_ids')
def unregistered_ids():
    """Allow admin to view all unregistered IDs."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ids WHERE is_registered = 0")
    unregistered_ids = cur.fetchall()
    conn.close()

    return render_template('unregistered_ids.html', unregistered_ids=unregistered_ids)

@app.route('/view_all_ids')
def view_all_ids():
    """Allow admin to view all IDs."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ids")
    all_ids = cur.fetchall()
    conn.close()

    return render_template('view_all_ids.html', all_ids=all_ids)

@app.route('/search_friends', methods=['GET', 'POST'])
def search_friends():
    """Allow users to search for friends by username or unique ID."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search_query = ''
    users = []

    if request.method == 'POST':
        search_query = request.form['search_query']
        
        conn = get_db_connection()
        cur = conn.cursor()
        # Search by username or unique ID
        cur.execute("""
            SELECT * FROM users 
            WHERE username LIKE ? OR unique_id LIKE ?
        """, ('%' + search_query + '%', '%' + search_query + '%'))
        users = cur.fetchall()
        conn.close()

    return render_template('search_friends.html', users=users, search_query=search_query)

@app.route('/send_friend_request/<int:receiver_id>', methods=['POST'])
def send_friend_request(receiver_id):
    """Send a friend request to another user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    # Check if a request already exists
    cur.execute("SELECT * FROM friend_requests WHERE sender_id = ? AND receiver_id = ?", (sender_id, receiver_id))
    existing_request = cur.fetchone()

    if existing_request:
        flash('Friend request already sent.', 'info')
    else:
        cur.execute("INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)", (sender_id, receiver_id))
        conn.commit()
        flash('Friend request sent!', 'success')

    conn.close()
    return redirect(url_for('search_friends'))

@app.route('/view_friends')
def view_friends():
    """View all friends of the logged-in user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT u.id, u.full_name, u.username
        FROM friends f
        JOIN users u ON (f.user_id = u.id OR f.friend_id = u.id)
        WHERE (f.user_id = ? OR f.friend_id = ?) AND u.id != ?
    ''', (session['user_id'], session['user_id'], session['user_id']))
    friends = cur.fetchall()
    conn.close()

    return render_template('view_friends.html', friends=friends)

@app.route('/view_received_requests')
def view_received_requests():
    """View all received friend requests."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT u.id, u.full_name, u.username, fr.id as request_id
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = ? AND fr.status = 'pending'
    ''', (session['user_id'],))
    requests = cur.fetchall()
    conn.close()

    return render_template('view_received_requests.html', requests=requests)

@app.route('/accept_friend_request/<int:request_id>')
def accept_friend_request(request_id):
    """Accept a friend request."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Update the request status to 'accepted'
    cur.execute('''
        UPDATE friend_requests
        SET status = 'accepted'
        WHERE id = ? AND receiver_id = ?
    ''', (request_id, session['user_id']))

    # Get the sender ID
    cur.execute('''
        SELECT sender_id
        FROM friend_requests
        WHERE id = ?
    ''', (request_id,))
    sender_id = cur.fetchone()['sender_id']

    # Add each other to the friends table
    cur.execute('''
        INSERT INTO friends (user_id, friend_id)
        VALUES (?, ?), (?, ?)
    ''', (session['user_id'], sender_id, sender_id, session['user_id']))

    conn.commit()
    conn.close()

    flash('Friend request accepted!', 'success')
    return redirect(url_for('view_received_requests'))

@app.route('/reject_friend_request/<int:request_id>')
def reject_friend_request(request_id):
    """Reject a friend request."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Update the request status to 'rejected'
    cur.execute('''
        UPDATE friend_requests
        SET status = 'rejected'
        WHERE id = ? AND receiver_id = ?
    ''', (request_id, session['user_id']))

    conn.commit()
    conn.close()

    flash('Friend request rejected!', 'info')
    return redirect(url_for('view_received_requests'))

if __name__ == '__main__':
    app.run(debug=True)
