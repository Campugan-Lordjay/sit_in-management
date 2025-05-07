from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, send_file
from flask import Flask, request, redirect, url_for
from flask import Flask, render_template, redirect, url_for, session, request
import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from io import BytesIO
import zipfile
import csv
from sqlalchemy import func
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management
UPLOAD_FOLDER = 'static/profile_pictures'  # Folder to store profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('login', error="You do not have permission to access this page."))
        return f(*args, **kwargs)
    return decorated_function

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define the admin password
admin_password = "admin_password"  # Replace with your desired password

# Generate a hashed password
hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')

print("Hashed Password:", hashed_password)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database initialization
DATABASE = 'users.db'

def init_db():
    """Initialize the SQLite database and create the users table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create the users table with proper constraints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            idNO VARCHAR(20) PRIMARY KEY,
            lastname VARCHAR(100),
            firstname VARCHAR(100),
            middlename VARCHAR(100),
            course VARCHAR(100),
            year_level VARCHAR(10),
            email VARCHAR(150),
            username VARCHAR(50) UNIQUE,
            password VARCHAR(100),
            session VARCHAR(20), 
            completed_sessions INTEGER DEFAULT 0,
            profile_picture TEXT,
            role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin'))
        );
    ''')

    # Add completed_sessions column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN completed_sessions INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        # Column already exists
        pass

    # Create the reservations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idno VARCHAR(20),
            date VARCHAR(10),
            time VARCHAR(5),
            session_type VARCHAR(50),
            language VARCHAR(20),
            status VARCHAR(20) DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add language column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE reservations ADD COLUMN language VARCHAR(20)')
    except sqlite3.OperationalError:
        # Column already exists
        pass

    # Create the feedback table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idno VARCHAR(20),
            session_id INTEGER,
            rating INTEGER CHECK (rating BETWEEN 1 AND 5),
            comment TEXT,
            category VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (idno) REFERENCES users(idNO),
            FOREIGN KEY (session_id) REFERENCES reservations(id)
        )
    ''')

    # Create the announcements table with VARCHAR columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS announcement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title VARCHAR(200) NOT NULL,
            content VARCHAR(1000) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create the lab schedules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lab_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            edp_code VARCHAR(20) NOT NULL,
            course VARCHAR(100) NOT NULL,
            time VARCHAR(50) NOT NULL,
            days VARCHAR(20) NOT NULL,
            room VARCHAR(20) NOT NULL,
            instructor VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' in session:
        return f"Welcome, {session['username']}! <br><a href='/logout'>Logout</a>"
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            # Connect to the database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Fetch the user record
            cursor.execute('''
                SELECT idNO, password, role
                FROM users
                WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()

            # Close the connection
            conn.close()

            # Check if the user exists
            if user is None:
                return render_template('login.html', error="Invalid username or password.")

            # Unpack user data
            idno, hashed_password, role = user

            # Verify the password
            if not check_password_hash(hashed_password, password):
                return render_template('login.html', error="Invalid username or password.")

            # Log the user in
            session['username'] = username
            session['role'] = role

            # Add a success message
            flash("Login successful!", "success")

            # Redirect based on the user's role
            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"Error during login: {e}")
            return render_template('login.html', error="An unexpected error occurred. Please try again.")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        idno = request.form.get('idno')
        lastname = request.form.get('lastname')
        firstname = request.form.get('firstname')
        middlename = request.form.get('middlename')
        course = request.form.get('course')
        year_level = request.form.get('year_level')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = 'user'  # Default role for new registrations

        # Validate password confirmation
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('register.html')

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            # Connect to the database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Check if username already exists
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash("Username already exists!", "error")
                return render_template('register.html')

            # Check if ID number already exists
            cursor.execute('SELECT idNO FROM users WHERE idNO = ?', (idno,))
            if cursor.fetchone():
                flash("ID Number already registered!", "error")
                return render_template('register.html')

            # Insert the user into the database
            cursor.execute('''
                INSERT INTO users (idNO, lastname, firstname, middlename, course, year_level, email, username, password, role, session)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (idno, lastname, firstname, middlename, course, year_level, email, username, hashed_password, role, '0'))
            
            conn.commit()
            conn.close()

            flash("Registration successful! You can now login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Error during registration: {e}")
            flash("An error occurred during registration. Please try again.", "error")
            return render_template('register.html')

    return render_template('register.html')
    
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login', error="You must be logged in to view the dashboard."))

    # Fetch user's profile information from the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT idNO, lastname, firstname, course, year_level, email, session, profile_picture 
        FROM users WHERE username = ?
    ''', (session['username'],))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        flash("User data not found.", "error")
        return redirect(url_for('login'))
    # Create a dictionary for easier access in the template
    user = {
        'idno': user_data[0],
        'lastname': user_data[1],
        'firstname': user_data[2],
        'course': user_data[3],
        'year_level': user_data[4],
        'email': user_data[5],
        'session': user_data[6],
        'profile_picture': user_data[7]  # Include the profile picture
    }

    # Check for query parameters in the URL
    params = request.args
    success_message = params.get('success')
    error_message = params.get('error')

    return render_template('dashboard.html', user=user, success=success_message, error=error_message)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Fetch data for admin dashboard (e.g., total users, total reservations, etc.)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get total users
    cursor.execute('SELECT COUNT(*) FROM users WHERE role != "admin"')
    total_users = cursor.fetchone()[0]
    
    # Get active sit-ins (assuming there's a status field)
    cursor.execute('SELECT COUNT(*) FROM reservations WHERE status = "Active"')
    active_sitins = cursor.fetchone()[0]
    
    # Get total sit-ins
    cursor.execute('SELECT COUNT(*) FROM reservations')
    total_sitins = cursor.fetchone()[0]
    
    conn.close()

    return render_template('admin_dashboard.html', 
                         total_users=total_users, 
                         active_sitins=active_sitins, 
                         total_sitins=total_sitins)

@app.route('/admin/students')
@admin_required
def admin_students():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of students per page
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get total number of students
    cursor.execute('SELECT COUNT(*) FROM users WHERE role != "admin"')
    total_students = cursor.fetchone()[0]
    
    # Calculate pagination values
    total_pages = (total_students + per_page - 1) // per_page
    offset = (page - 1) * per_page
    
    # Get students for current page
    cursor.execute('''
        SELECT idNO, lastname, firstname, course, year_level, 
               CASE WHEN session > 0 THEN 1 ELSE 0 END as is_online
        FROM users 
        WHERE role != "admin"
        ORDER BY lastname, firstname
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    students = [
        {
            'idno': row[0],
            'lastname': row[1],
            'firstname': row[2],
            'course': row[3],
            'year_level': row[4],
            'is_online': bool(row[5])
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    return render_template('admin_students.html',
                         students=students,
                         page=page,
                         total_pages=total_pages,
                         has_prev=page > 1,
                         has_next=page < total_pages)

@app.route('/admin/students/filter')
@admin_required
def filter_students():
    course = request.args.get('course', '')
    year = request.args.get('year', '')
    status = request.args.get('status', '')
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    query = '''
        SELECT idNO, lastname, firstname, course, year_level,
               CASE WHEN session > 0 THEN 1 ELSE 0 END as is_online
        FROM users 
        WHERE role != "admin"
    '''
    params = []
    
    if course:
        query += ' AND course = ?'
        params.append(course)
    if year:
        query += ' AND year_level = ?'
        params.append(year)
    if status:
        if status == 'online':
            query += ' AND session > 0'
        else:
            query += ' AND session = 0'
    
    query += ' ORDER BY lastname, firstname'
    
    cursor.execute(query, params)
    students = [
        {
            'idno': row[0],
            'lastname': row[1],
            'firstname': row[2],
            'course': row[3],
            'year_level': row[4],
            'is_online': bool(row[5])
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    return jsonify(students)

@app.route('/admin/student/<string:idno>')
@admin_required
def get_student(idno):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT idNO, lastname, firstname, course, year_level, email,
               CASE WHEN session > 0 THEN 1 ELSE 0 END as is_online
        FROM users 
        WHERE idNO = ?
    ''', (idno,))
    
    row = cursor.fetchone()
    if row is None:
        return jsonify({'error': 'Student not found'}), 404
        
    student = {
        'idno': row[0],
        'lastname': row[1],
        'firstname': row[2],
        'course': row[3],
        'year_level': row[4],
        'email': row[5],
        'is_online': bool(row[6])
    }
    
    conn.close()
    return jsonify(student)

@app.route('/admin/student/edit/<string:idno>', methods=['GET', 'POST'])
@admin_required
def edit_student(idno):
    if request.method == 'POST':
        # Get form data
        course = request.form.get('course')
        year_level = request.form.get('year_level')
        email = request.form.get('email')
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET course = ?, year_level = ?, email = ?
                WHERE idNO = ?
            ''', (course, year_level, email, idno))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'message': 'Student updated successfully'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    # GET request - return student data for editing
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE idNO = ?', (idno,))
    student = cursor.fetchone()
    
    conn.close()
    
    if student is None:
        return jsonify({'error': 'Student not found'}), 404
        
    return jsonify({
        'idno': student[0],
        'lastname': student[1],
        'firstname': student[2],
        'course': student[4],
        'year_level': student[5],
        'email': student[6]
    })

@app.route('/update_profile', methods=['POST'])
def update_profile():
    try:
        # Get form data
        idno = request.form.get('idno')
        lastname = request.form.get('lastname')  # Hidden input for lastname
        firstname = request.form.get('firstname')  # Hidden input for firstname
        email = request.form.get('email')
        session = request.form.get('session')

        # Connect to the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Update the user's profile information
        cursor.execute('''
            UPDATE users
            SET lastname = ?, firstname = ?, email = ?, session = ?
            WHERE idNO = ?
        ''', (lastname, firstname, email, session, idno))

        # Commit changes and close the connection
        conn.commit()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard', success="Profile updated successfully!"))
    except Exception as e:
        print(f"Error during profile update: {e}")
        flash("An unexpected error occurred. Please try again.", "error")
        return redirect(url_for('dashboard', error="An unexpected error occurred."))

@app.route('/reservation', methods=['GET', 'POST'])
def reservation():
    if 'username' not in session:
        return redirect(url_for('login', error="You must be logged in to make a reservation."))

    if request.method == 'POST':
        try:
            # Get the form data
            idno = request.form.get('idno')
            date = request.form.get('date')
            time = request.form.get('time')
            lab_room = request.form.get('session_type')  # This now contains the lab room
            language = request.form.get('language')  # New field for programming language

            # Validate the data
            if not all([idno, date, time, lab_room, language]):
                return jsonify({
                    'success': False,
                    'message': 'All fields are required'
                }), 400

            # Save the reservation to the database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # First check if the student exists
            cursor.execute('SELECT idNO FROM users WHERE idNO = ?', (idno,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({
                    'success': False,
                    'message': 'Student ID not found'
                }), 404

            # Check if there's already a reservation for this room at this time
            cursor.execute('''
                SELECT id FROM reservations 
                WHERE date = ? AND time = ? AND session_type = ? AND status != 'Rejected'
            ''', (date, time, lab_room))
            
            if cursor.fetchone():
                conn.close()
                return jsonify({
                    'success': False,
                    'message': 'This laboratory room is already reserved for the selected time'
                }), 400

            # Insert the reservation
            cursor.execute('''
                INSERT INTO reservations (idno, date, time, session_type, language, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (idno, date, time, f"Room {lab_room}", language, "Pending"))
            
            conn.commit()
            conn.close()

            return jsonify({
                'success': True,
                'message': 'Reservation submitted successfully!'
            })

        except Exception as e:
            print(f"Error submitting reservation: {e}")
            return jsonify({
                'success': False,
                'message': 'An error occurred while submitting the reservation'
            }), 500

    # Render the reservation form for GET requests
    return render_template('reservation.html', user=session.get('user'))

@app.route('/admin/reservations')
@admin_required
def admin_reservations():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reservations ORDER BY created_at DESC')
    reservations = cursor.fetchall()
    conn.close()

    return render_template('admin_reservations.html', reservations=reservations)

@app.route('/admin/post-announcement', methods=['GET', 'POST'])
@admin_required
def post_announcement():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        if not title or not content:
            return render_template('post_announcement.html', error="Title and content are required.")

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO announcements (title, content) VALUES (?, ?)', (title, content))
            conn.commit()
            conn.close()

            return redirect(url_for('admin_dashboard', success="Announcement posted successfully!"))
        except Exception as e:
            print(f"Error posting announcement: {e}")
            return render_template('post_announcement.html', error="Failed to post announcement. Please try again.")

    return render_template('post_announcement.html')

@app.route('/remaining-session')
def remaining_session():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('remaining_session.html')

@app.route('/sit-in-rules')
def sit_in_rules():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('sit_in_rules.html')

@app.route('/lab-rules')
def lab_rules():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('lab_rules.html')

@app.route('/reservation-history')
def reservation_history():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        # Connect to the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get the user's ID number from the session
        cursor.execute('SELECT idNO FROM users WHERE username = ?', (session['username'],))
        user_id = cursor.fetchone()[0]
        
        # Get filter parameters
        date_filter = request.args.get('date')
        status_filter = request.args.get('status')
        language_filter = request.args.get('language')
        
        # Base query
        query = '''
            SELECT r.idno, u.firstname || ' ' || u.lastname as fullname, 
                   r.date, r.time, r.session_type, r.language, r.status, r.created_at
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            WHERE r.idno = ?
        '''
        params = [user_id]
        
        # Add filters if provided
        if date_filter:
            query += ' AND r.date = ?'
            params.append(date_filter)
        if status_filter and status_filter != 'all':
            query += ' AND r.status = ?'
            params.append(status_filter)
        if language_filter and language_filter != 'all':
            query += ' AND r.language = ?'
            params.append(language_filter)
            
        # Add ordering
        query += ' ORDER BY r.created_at DESC'
        
        # Execute the query
        cursor.execute(query, params)
        reservations = cursor.fetchall()
        
        # Format the reservations data for the template
        formatted_reservations = []
        for res in reservations:
            formatted_reservations.append({
                'idno': res[0],
                'fullname': res[1],
                'date': res[2],
                'time': res[3],
                'session_type': res[4],
                'language': res[5],
                'status': res[6],
                'created_at': res[7]
            })
        
        conn.close()
        
        return render_template('reservation_history.html', reservations=formatted_reservations)
        
    except Exception as e:
        print(f"Error fetching reservation history: {e}")
        flash("Error loading reservation history", "error")
        return redirect(url_for('dashboard'))

@app.route('/lab-history')
def lab_history():
    # Fetch all lab schedules
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM lab_schedules ORDER BY created_at DESC')
    schedules = cursor.fetchall()
    conn.close()

    # Format the schedules data for the template
    formatted_schedules = []
    for schedule in schedules:
        formatted_schedules.append({
            'edp_code': schedule[1],
            'course': schedule[2],
            'time': schedule[3],
            'days': schedule[4],
            'room': schedule[5],
            'instructor': schedule[6],
            'created_at': schedule[7]
        })

    return render_template('lab_history.html', schedules=formatted_schedules)

@app.route('/resources')
def resources():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('resources.html')

@app.route('/download-resource/<string:type>')
def download_resource(type):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        # Set the directory where resources are stored
        resource_dir = os.path.join(app.root_path, 'static', 'resources')
        
        # Create a ZIP file for the requested file type
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            # Walk through the resource directory
            for root, dirs, files in os.walk(resource_dir):
                for file in files:
                    # Check file extension based on type
                    if type == 'pdf' and file.lower().endswith('.pdf'):
                        file_path = os.path.join(root, file)
                        zf.write(file_path, file)
                    elif type == 'doc' and (file.lower().endswith('.doc') or file.lower().endswith('.docx')):
                        file_path = os.path.join(root, file)
                        zf.write(file_path, file)
                    elif type == 'image' and file.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                        file_path = os.path.join(root, file)
                        zf.write(file_path, file)
        
        # Seek to the beginning of the file
        memory_file.seek(0)
        
        # Return the ZIP file
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{type}_files.zip'
        )
    except Exception as e:
        flash(f'Error downloading {type} files: {str(e)}', 'error')
        return redirect(url_for('resources'))

@app.route('/sit-in-history')
def sit_in_history():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Get filter parameters
        status = request.args.get('status', 'all')
        date = request.args.get('date')
        page = request.args.get('page', 1, type=int)
        per_page = 10

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Get the user's ID number
        cursor.execute('SELECT idNO FROM users WHERE username = ?', (session['username'],))
        user_id = cursor.fetchone()[0]

        # Base query with feedback join
        query = '''
            SELECT r.id, r.idno, u.firstname, u.lastname, r.date, r.time, 
                   r.session_type, r.language, r.status, r.created_at,
                   f.comment as report
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            LEFT JOIN feedback f ON r.id = f.session_id AND f.category = 'sit-in report'
            WHERE r.idno = ?
        '''
        params = [user_id]

        # Add filters
        if status != 'all':
            query += ' AND r.status = ?'
            params.append(status)
        if date:
            query += ' AND r.date = ?'
            params.append(date)

        # Get total count for pagination
        count_query = f"SELECT COUNT(*) FROM ({query})"
        cursor.execute(count_query, params)
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + per_page - 1) // per_page

        # Add pagination
        query += ' ORDER BY r.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        # Execute final query
        cursor.execute(query, params)
        records = [
            {
                'id': row[0],
                'idno': row[1],
                'firstname': row[2],
                'lastname': row[3],
                'date': row[4],
                'time': row[5],
                'session_type': row[6],
                'language': row[7],
                'status': row[8],
                'created_at': row[9],
                'report': row[10]
            }
            for row in cursor.fetchall()
        ]

        conn.close()

        return render_template('sit_in_history.html',
                             records=records,
                             page=page,
                             total_pages=total_pages,
                             has_prev=page > 1,
                             has_next=page < total_pages,
                             current_status=status,
                             current_date=date)

    except Exception as e:
        print(f"Error fetching sit-in history: {e}")
        flash("Error loading sit-in history", "error")
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login', error="You must be logged in to view your profile."))

    if request.method == 'POST':
        try:
            # Get form data
            idno = request.form.get('idno')
            lastname = request.form.get('lastname')
            firstname = request.form.get('firstname')
            email = request.form.get('email')
            course = request.form.get('course')
            year_level = request.form.get('year_level')
            session_count = request.form.get('session')
            
            # Handle profile picture upload
            profile_picture = None
            if 'profilePicture' in request.files:
                file = request.files['profilePicture']
                if file and file.filename != '':
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        # Save the file
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        profile_picture = filename

            # Connect to database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Update user information
            if profile_picture:
                cursor.execute('''
                    UPDATE users 
                    SET lastname = ?, firstname = ?, email = ?, course = ?, year_level = ?, session = ?, profile_picture = ?
                    WHERE idNO = ?
                ''', (lastname, firstname, email, course, year_level, session_count, profile_picture, idno))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET lastname = ?, firstname = ?, email = ?, course = ?, year_level = ?, session = ?
                    WHERE idNO = ?
                ''', (lastname, firstname, email, course, year_level, session_count, idno))

            conn.commit()
            conn.close()

            # Return JSON response for AJAX request
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully!'
            })

        except Exception as e:
            print(f"Error updating profile: {e}")
            return jsonify({
                'success': False,
                'message': 'An error occurred while updating your profile.'
            }), 500

    # Fetch user's profile information from the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT idNO, lastname, firstname, middlename, course, year_level, email, session, profile_picture 
        FROM users WHERE username = ?
    ''', (session['username'],))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        flash("User data not found.", "error")
        return redirect(url_for('login'))

    # Create a dictionary for easier access in the template
    user = {
        'idno': user_data[0],
        'lastname': user_data[1],
        'firstname': user_data[2],
        'middlename': user_data[3],
        'course': user_data[4],
        'year_level': user_data[5],
        'email': user_data[6],
        'session': user_data[7],
        'profile_picture': user_data[8]
    }

    return render_template('profile.html', user=user)

@app.route('/lab-schedules', methods=['GET', 'POST'])
@admin_required
def lab_schedules():
    if request.method == 'POST':
        try:
            # Get form data
            edp_code = request.form.get('edp_code')
            course = request.form.get('course')
            time = request.form.get('time')
            days = request.form.get('days')
            room = request.form.get('room')

            # Connect to database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Insert new schedule
            cursor.execute('''
                INSERT INTO lab_schedules (edp_code, course, time, days, room)
                VALUES (?, ?, ?, ?, ?)
            ''', (edp_code, course, time, days, room))

            conn.commit()
            conn.close()

            flash("Schedule added successfully!", "success")
            return redirect(url_for('lab_schedules'))

        except Exception as e:
            print(f"Error adding schedule: {e}")
            flash("An error occurred while adding the schedule.", "error")
            return redirect(url_for('lab_schedules'))

    # Fetch all lab schedules
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM lab_schedules ORDER BY created_at DESC')
    schedules = cursor.fetchall()
    conn.close()

    # Format the schedules data for the template
    formatted_schedules = []
    for schedule in schedules:
        formatted_schedules.append({
            'id': schedule[0],
            'edp_code': schedule[1],
            'course': schedule[2],
            'time': schedule[3],
            'days': schedule[4],
            'room': schedule[5],
            'created_at': schedule[6]
        })

    return render_template('view-lab_schedules.html', schedules=formatted_schedules)

@app.route('/edit-schedule/<int:schedule_id>', methods=['POST'])
def edit_schedule(schedule_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401

    try:
        # Get form data
        edp_code = request.form.get('edp_code')
        course = request.form.get('course')
        time = request.form.get('time')
        days = request.form.get('days')
        room = request.form.get('room')
        instructor = request.form.get('instructor')

        # Validate required fields
        if not all([edp_code, course, time, days, room, instructor]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        # Connect to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Update schedule
        cursor.execute('''
            UPDATE lab_schedules 
            SET edp_code = ?, course = ?, time = ?, days = ?, room = ?, instructor = ?
            WHERE id = ?
        ''', (edp_code, course, time, days, room, instructor, schedule_id))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Schedule updated successfully'})

    except Exception as e:
        print(f"Error updating schedule: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating schedule'}), 500

@app.route('/delete-schedule/<int:schedule_id>', methods=['POST'])
def delete_schedule(schedule_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401

    try:
        # Connect to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Delete schedule
        cursor.execute('DELETE FROM lab_schedules WHERE id = ?', (schedule_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'message': 'Schedule not found'}), 404

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Schedule deleted successfully'})

    except Exception as e:
        print(f"Error deleting schedule: {str(e)}")
        return jsonify({'success': False, 'message': 'Error deleting schedule'}), 500

@app.route('/add-schedule', methods=['POST'])
def add_schedule():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    try:
        # Get form data
        edp_code = request.form.get('edp_code')
        course = request.form.get('course')
        time = request.form.get('time')
        days = request.form.get('days')
        room = request.form.get('room')
        instructor = request.form.get('instructor')

        # Validate required fields
        if not all([edp_code, course, time, days, room, instructor]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        # Connect to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Insert new schedule
        cursor.execute('''
            INSERT INTO lab_schedules (edp_code, course, time, days, room, instructor, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (edp_code, course, time, days, room, instructor, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Schedule added successfully'})

    except Exception as e:
        print(f"Error adding schedule: {str(e)}")
        return jsonify({'success': False, 'message': 'Error adding schedule'}), 500

@app.route('/admin/upload-lab-schedule', methods=['GET', 'POST'])
@admin_required
def upload_lab_schedule():
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Check if this is a delete action
            if data and data.get('action') == 'delete':
                edp_code = data.get('edp_code')
                if not edp_code:
                    return jsonify({'success': False, 'message': 'EDP Code is required'}), 400

                # Delete the schedule
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()
                
                # Check if schedule exists
                cursor.execute('SELECT * FROM lab_schedules WHERE edp_code = ?', (edp_code,))
                if not cursor.fetchone():
                    conn.close()
                    return jsonify({'success': False, 'message': 'Schedule not found'}), 404
                
                # Delete the schedule
                cursor.execute('DELETE FROM lab_schedules WHERE edp_code = ?', (edp_code,))
                conn.commit()
                conn.close()
                
                return jsonify({
                    'success': True,
                    'message': 'Schedule deleted successfully'
                })
            
            # If not delete action, then it's an add/update action
            edp_code = data.get('edp_code')
            course = data.get('course')
            time = data.get('time')
            days = data.get('days')
            room = data.get('room')
            instructor = data.get('instructor')

            # Validate required fields
            if not all([edp_code, course, time, days, room, instructor]):
                return jsonify({'success': False, 'message': 'All fields are required'}), 400

            # Connect to database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Check if schedule with same EDP code already exists
            cursor.execute('SELECT id FROM lab_schedules WHERE edp_code = ?', (edp_code,))
            existing_schedule = cursor.fetchone()

            if existing_schedule:
                # Update existing schedule
                cursor.execute('''
                    UPDATE lab_schedules 
                    SET course = ?, time = ?, days = ?, room = ?, instructor = ?
                    WHERE edp_code = ?
                ''', (course, time, days, room, instructor, edp_code))
                message = 'Schedule updated successfully'
            else:
                # Insert new schedule
                cursor.execute('''
                    INSERT INTO lab_schedules (edp_code, course, time, days, room, instructor)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (edp_code, course, time, days, room, instructor))
                message = 'Schedule added successfully'

            conn.commit()
            conn.close()

            return jsonify({
                'success': True,
                'message': message
            })

        except Exception as e:
            print(f"Error handling schedule: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'An error occurred while processing the request'
            }), 500

    # GET request - show upload form
    # Fetch existing schedules for display
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT edp_code, course, time, days, room, instructor, created_at
        FROM lab_schedules
        ORDER BY created_at DESC
    ''')
    schedules = [
        {
            'edp_code': row[0],
            'course': row[1],
            'time': row[2],
            'days': row[3],
            'room': row[4],
            'instructor': row[5],
            'created_at': row[6]
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    return render_template('upload_lab_schedule.html', schedules=schedules)

@app.route('/admin/upload-resources', methods=['GET', 'POST'])
@admin_required
def upload_resources():
    if request.method == 'POST':
        try:
            # Check if any file was uploaded
            if 'resource' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('upload_resources'))

            file = request.files['resource']
            resource_type = request.form.get('resource_type')  # pdf, doc, or image

            # If user does not select file
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('upload_resources'))

            # Validate file type
            allowed_extensions = {
                'pdf': {'pdf'},
                'doc': {'doc', 'docx'},
                'image': {'jpg', 'jpeg', 'png', 'gif'}
            }

            if resource_type not in allowed_extensions:
                flash('Invalid resource type', 'error')
                return redirect(url_for('upload_resources'))

            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()

            if file_ext not in allowed_extensions[resource_type]:
                flash(f'File type not allowed for {resource_type}', 'error')
                return redirect(url_for('upload_resources'))

            # Create resource directory if it doesn't exist
            resource_dir = os.path.join(app.root_path, 'static', 'resources', resource_type)
            os.makedirs(resource_dir, exist_ok=True)

            # Save the file
            file_path = os.path.join(resource_dir, filename)
            file.save(file_path)

            flash('Resource uploaded successfully', 'success')
            return redirect(url_for('upload_resources'))

        except Exception as e:
            flash(f'Error uploading resource: {str(e)}', 'error')
            return redirect(url_for('upload_resources'))

    # GET request - show upload form and list existing resources
    resources = {
        'pdf': [],
        'doc': [],
        'image': []
    }

    # Get list of existing resources
    resource_base_dir = os.path.join(app.root_path, 'static', 'resources')
    for resource_type in resources.keys():
        resource_dir = os.path.join(resource_base_dir, resource_type)
        if os.path.exists(resource_dir):
            resources[resource_type] = [
                {
                    'name': f,
                    'size': os.path.getsize(os.path.join(resource_dir, f)),
                    'modified': os.path.getmtime(os.path.join(resource_dir, f))
                }
                for f in os.listdir(resource_dir)
                if os.path.isfile(os.path.join(resource_dir, f))
            ]

    return render_template('upload_resources.html', resources=resources)

@app.route('/admin/delete-resource/<string:resource_type>/<string:filename>')
@admin_required
def delete_resource(resource_type, filename):
    try:
        if resource_type not in ['pdf', 'doc', 'image']:
            return jsonify({'success': False, 'message': 'Invalid resource type'}), 400

        resource_path = os.path.join(
            app.root_path, 'static', 'resources', 
            resource_type, secure_filename(filename)
        )

        if os.path.exists(resource_path):
            os.remove(resource_path)
            return jsonify({'success': True, 'message': 'Resource deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Resource not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Helper function to check if a file extension is allowed
def allowed_file(filename, resource_type):
    allowed_extensions = {
        'pdf': {'pdf'},
        'doc': {'doc', 'docx'},
        'image': {'jpg', 'jpeg', 'png', 'gif'}
    }
    
    if '.' not in filename:
        return False
        
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions.get(resource_type, set())

@app.route('/admin/sitin')
@admin_required
def admin_sitin():
    # Get filter parameters
    status = request.args.get('status', 'all')
    date = request.args.get('date')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get stats for each status
    cursor.execute('''
        SELECT status, COUNT(*) as count
        FROM reservations
        GROUP BY status
    ''')
    stats_rows = cursor.fetchall()
    stats = {
        'pending': 0,
        'approved': 0,
        'rejected': 0,
        'completed': 0
    }
    for row in stats_rows:
        if row[0]:
            stats[row[0].lower()] = row[1]

    # Base query
    query = '''
        SELECT r.id, r.idno, u.firstname, u.lastname, r.date, r.time, 
               r.session_type, r.language, r.status, r.created_at
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        WHERE 1=1
    '''
    params = []

    # Add filters
    if status != 'all':
        query += ' AND r.status = ?'
        params.append(status)
    if date:
        query += ' AND r.date = ?'
        params.append(date)

    # Get total count for pagination
    count_query = f"SELECT COUNT(*) FROM ({query})"
    cursor.execute(count_query, params)
    total_items = cursor.fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Add pagination
    query += ' ORDER BY r.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    # Execute final query
    cursor.execute(query, params)
    reservations = [
        {
            'id': row[0],
            'idno': row[1],
            'firstname': row[2],
            'lastname': row[3],
            'date': row[4],
            'time': row[5],
            'session_type': row[6],
            'language': row[7],
            'status': row[8],
            'created_at': row[9]
        }
        for row in cursor.fetchall()
    ]

    conn.close()

    return render_template('admin_sitin.html',
                         reservations=reservations,
                         page=page,
                         total_pages=total_pages,
                         has_prev=page > 1,
                         has_next=page < total_pages,
                         status=status,
                         date=date,
                         stats=stats)  # Added stats to the template context

@app.route('/admin/sitin/update-status', methods=['POST'])
@admin_required
def update_sitin_status():
    try:
        reservation_id = request.form.get('reservation_id')
        new_status = request.form.get('status')

        if not reservation_id or not new_status:
            return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

        if new_status not in ['Approved', 'Rejected', 'Pending', 'Completed']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Get the current status
        cursor.execute('SELECT status FROM reservations WHERE id = ?', (reservation_id,))
        current_status = cursor.fetchone()[0]

        # Update the reservation status
        cursor.execute('''
            UPDATE reservations 
            SET status = ?
            WHERE id = ?
        ''', (new_status, reservation_id))

        # If changing from any status to Completed, update user's completed sessions
        if new_status == 'Completed' and current_status != 'Completed':
            cursor.execute('''
                UPDATE users 
                SET completed_sessions = completed_sessions + 1
                WHERE idNO = (
                    SELECT idno FROM reservations WHERE id = ?
                )
            ''', (reservation_id,))

        # If approving a new reservation
        if new_status == 'Approved' and current_status != 'Approved':
            cursor.execute('''
                UPDATE users 
                SET session = session + 1
                WHERE idNO = (
                    SELECT idno FROM reservations WHERE id = ?
                )
            ''', (reservation_id,))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Reservation status updated to {new_status}'
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/sitin/delete/<int:reservation_id>', methods=['POST'])
@admin_required
def delete_sitin(reservation_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Check if reservation exists
        cursor.execute('SELECT id FROM reservations WHERE id = ?', (reservation_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Reservation not found'}), 404

        # Delete the reservation
        cursor.execute('DELETE FROM reservations WHERE id = ?', (reservation_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Reservation deleted successfully'
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/sitin/view/<int:reservation_id>')
@admin_required
def view_sitin(reservation_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get detailed reservation information
    cursor.execute('''
        SELECT r.*, u.firstname, u.lastname, u.course, u.year_level
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        WHERE r.id = ?
    ''', (reservation_id,))
    
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'success': False, 'message': 'Reservation not found'}), 404

    reservation = {
        'id': row[0],
        'idno': row[1],
        'date': row[2],
        'time': row[3],
        'session_type': row[4],
        'reason': row[5],
        'status': row[6],
        'created_at': row[7],
        'student_name': f"{row[9]} {row[8]}",  # firstname lastname
        'course': row[10],
        'year_level': row[11]
    }

    return jsonify(reservation)

@app.route('/admin/sitin-records')
@admin_required
def admin_sitin_records():
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    course = request.args.get('course')
    year_level = request.args.get('year_level')
    status = request.args.get('status', 'all')  # New status filter
    page = request.args.get('page', 1, type=int)
    per_page = 10

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Base query
    query = '''
        SELECT r.id, r.idno, u.firstname, u.lastname, u.course, u.year_level,
               r.date, r.time, r.session_type, r.status, r.created_at,
               r.language
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        WHERE r.status IN ('Approved', 'Completed')
    '''
    params = []

    # Add filters
    if status != 'all':
        query += ' AND r.status = ?'
        params.append(status)
    if start_date and end_date:
        query += ' AND r.date BETWEEN ? AND ?'
        params.extend([start_date, end_date])
    if course:
        query += ' AND u.course = ?'
        params.append(course)
    if year_level:
        query += ' AND u.year_level = ?'
        params.append(year_level)

    # Get total count for pagination
    count_query = f"SELECT COUNT(*) FROM ({query})"
    cursor.execute(count_query, params)
    total_items = cursor.fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Add pagination
    query += ' ORDER BY r.date DESC, r.time DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    # Execute final query
    cursor.execute(query, params)
    records = [
        {
            'id': row[0],
            'idno': row[1],
            'firstname': row[2],
            'lastname': row[3],
            'course': row[4],
            'year_level': row[5],
            'date': row[6],
            'time': row[7],
            'session_type': row[8],
            'status': row[9],
            'created_at': row[10],
            'language': row[11]
        }
        for row in cursor.fetchall()
    ]

    # Get available courses and year levels for filters
    cursor.execute('SELECT DISTINCT course FROM users WHERE course IS NOT NULL')
    courses = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT year_level FROM users WHERE year_level IS NOT NULL')
    year_levels = [row[0] for row in cursor.fetchall()]

    conn.close()

    return render_template('admin_sitin_records.html',
                         records=records,
                         page=page,
                         total_pages=total_pages,
                         has_prev=page > 1,
                         has_next=page < total_pages,
                         courses=courses,
                         year_levels=year_levels,
                         current_course=course,
                         current_year=year_level,
                         current_status=status,
                         start_date=start_date,
                         end_date=end_date)

@app.route('/admin/sitin-records/export')
@admin_required
def export_sitin_records():
    try:
        # Get filter parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        course = request.args.get('course')
        year_level = request.args.get('year_level')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Query with filters
        query = '''
            SELECT r.idno, u.firstname, u.lastname, u.course, u.year_level,
                   r.date, r.time, r.session_type, r.status, r.created_at
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            WHERE r.status = 'Completed'
        '''
        params = []

        if start_date and end_date:
            query += ' AND r.date BETWEEN ? AND ?'
            params.extend([start_date, end_date])
        if course:
            query += ' AND u.course = ?'
            params.append(course)
        if year_level:
            query += ' AND u.year_level = ?'
            params.append(year_level)

        query += ' ORDER BY r.date DESC, r.time DESC'
        
        cursor.execute(query, params)
        records = cursor.fetchall()
        conn.close()

        # Create CSV in memory
        output = BytesIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID Number', 'First Name', 'Last Name', 'Course', 'Year Level',
                        'Date', 'Time', 'Session Type', 'Status', 'Created At'])
        
        # Write data
        for row in records:
            writer.writerow([
                row[0],  # ID Number
                row[1],  # First Name
                row[2],  # Last Name
                row[3],  # Course
                row[4],  # Year Level
                row[5],  # Date
                row[6],  # Time
                row[7],  # Session Type
                row[8],  # Status
                row[9]   # Created At
            ])
        
        # Prepare response
        output.seek(0)
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'sitin_records_{datetime.now().strftime("%Y%m%d")}.csv'
        )

    except Exception as e:
        flash(f'Error exporting records: {str(e)}', 'error')
        return redirect(url_for('admin_sitin_records'))

@app.route('/admin/sitin-records/view/<int:record_id>')
@admin_required
def view_sitin_record(record_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get detailed record information
    cursor.execute('''
        SELECT r.*, u.firstname, u.lastname, u.course, u.year_level
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        WHERE r.id = ?
    ''', (record_id,))
    
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'success': False, 'message': 'Record not found'}), 404

    record = {
        'id': row[0],
        'idno': row[1],
        'date': row[2],
        'time': row[3],
        'session_type': row[4],
        'language': row[5],
        'status': row[6],
        'created_at': row[7],
        'student_name': f"{row[9]} {row[8]}",
        'course': row[10],
        'year_level': row[11]
    }

    return jsonify(record)

@app.route('/admin/sitin-report')
@admin_required
def admin_sitin_report():
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    course = request.args.get('course')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Base query for overall statistics
    stats_query = '''
        SELECT 
            COUNT(DISTINCT r.idno) as total_students,
            COUNT(r.id) as total_sessions,
            AVG(CASE WHEN r.status = 'Completed' THEN 1 ELSE 0 END) * 100 as completion_rate
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        WHERE 1=1
    '''
    params = []

    if start_date and end_date:
        stats_query += ' AND r.date BETWEEN ? AND ?'
        params.extend([start_date, end_date])
    if course:
        stats_query += ' AND u.course = ?'
        params.append(course)

    cursor.execute(stats_query, params)
    stats_row = cursor.fetchone()
    overall_stats = {
        'total_students': stats_row[0],
        'total_sessions': stats_row[1],
        'completion_rate': round(stats_row[2], 2) if stats_row[2] else 0
    }

    # Query for course distribution
    cursor.execute('''
        SELECT u.course, COUNT(DISTINCT r.idno) as student_count,
               COUNT(r.id) as session_count
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        GROUP BY u.course
        ORDER BY session_count DESC
    ''')
    course_stats = [
        {
            'course': row[0] or 'Unspecified',
            'student_count': row[1],
            'session_count': row[2]
        }
        for row in cursor.fetchall()
    ]

    # Query for programming language distribution
    cursor.execute('''
        SELECT language as type, COUNT(*) as count
        FROM reservations
        WHERE language IS NOT NULL
        GROUP BY language
        ORDER BY count DESC
    ''')
    session_types = [
        {
            'type': row[0],
            'count': row[1]
        }
        for row in cursor.fetchall()
    ]

    # Query for detailed reports
    reports_query = '''
        SELECT r.date, u.firstname, u.lastname, u.course,
               r.session_type, r.language, r.status, f.comment as message
        FROM reservations r
        JOIN users u ON r.idno = u.idNO
        LEFT JOIN feedback f ON r.id = f.session_id
        WHERE f.category = 'sit-in report'
    '''
    params = []

    if start_date and end_date:
        reports_query += ' AND r.date BETWEEN ? AND ?'
        params.extend([start_date, end_date])
    if course:
        reports_query += ' AND u.course = ?'
        params.append(course)

    reports_query += ' ORDER BY r.date DESC'

    cursor.execute(reports_query, params)
    reports = [
        {
            'date': row[0],
            'student_name': f"{row[1]} {row[2]}",
            'course': row[3],
            'session_type': row[4],
            'language': row[5],
            'status': row[6],
            'message': row[7] or 'No report submitted'
        }
        for row in cursor.fetchall()
    ]

    # Get available courses for filter
    cursor.execute('SELECT DISTINCT course FROM users WHERE course IS NOT NULL')
    available_courses = [row[0] for row in cursor.fetchall()]

    conn.close()

    return render_template('admin_sitin_report.html',
                         overall_stats=overall_stats,
                         course_stats=course_stats,
                         session_types=session_types,
                         reports=reports,
                         available_courses=available_courses,
                         current_course=course,
                         start_date=start_date,
                         end_date=end_date)

@app.route('/admin/sitin-report/export')
@admin_required
def export_sitin_report():
    try:
        # Get filter parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        course = request.args.get('course')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Prepare data for export
        data = []
        
        # Overall statistics
        cursor.execute('''
            SELECT COUNT(DISTINCT r.idno) as total_students,
                   COUNT(r.id) as total_sessions,
                   AVG(CASE WHEN r.status = 'Completed' THEN 1 ELSE 0 END) * 100 as completion_rate
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            WHERE (? IS NULL OR r.date >= ?)
              AND (? IS NULL OR r.date <= ?)
              AND (? IS NULL OR u.course = ?)
        ''', [start_date, start_date, end_date, end_date, course, course])
        
        stats = cursor.fetchone()
        data.append(['Overall Statistics'])
        data.append(['Total Students', stats[0]])
        data.append(['Total Sessions', stats[1]])
        data.append(['Completion Rate', f"{round(stats[2], 2)}%"])
        data.append([])  # Empty row for spacing

        # Course distribution
        data.append(['Course Distribution'])
        data.append(['Course', 'Student Count', 'Session Count'])
        cursor.execute('''
            SELECT u.course, COUNT(DISTINCT r.idno), COUNT(r.id)
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            GROUP BY u.course
            ORDER BY COUNT(r.id) DESC
        ''')
        data.extend(cursor.fetchall())
        data.append([])

        # Programming language distribution
        data.append(['Programming Language Distribution'])
        data.append(['Language', 'Usage Count'])
        cursor.execute('''
            SELECT language, COUNT(*) as count
            FROM reservations
            WHERE language IS NOT NULL
            GROUP BY language
            ORDER BY count DESC
        ''')
        data.extend(cursor.fetchall())
        data.append([])

        # Detailed reports
        data.append(['Detailed Reports'])
        data.append(['Date', 'Student Name', 'Course', 'Laboratory Room', 
                    'Programming Language', 'Status', 'Report Message'])
        cursor.execute('''
            SELECT r.date, u.firstname || ' ' || u.lastname, u.course,
                   r.session_type, r.language, r.status, f.comment
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            LEFT JOIN feedback f ON r.id = f.session_id
            WHERE f.category = 'sit-in report'
            ORDER BY r.date DESC
        ''')
        data.extend(cursor.fetchall())

        conn.close()

        # Create CSV in memory
        output = BytesIO()
        writer = csv.writer(output)
        writer.writerows(data)

        # Prepare response
        output.seek(0)
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'sitin_report_{datetime.now().strftime("%Y%m%d")}.csv'
        )

    except Exception as e:
        flash(f'Error exporting report: {str(e)}', 'error')
        return redirect(url_for('admin_sitin_report'))

@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    try:
        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        per_page = 10

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Get feedback statistics
        cursor.execute('''
            SELECT 
                COALESCE(ROUND(AVG(rating), 2), 0) as avg_rating,
                COUNT(*) as total_feedback,
                ROUND(
                    (CAST(COUNT(CASE WHEN rating >= 4 THEN 1 END) AS FLOAT) / 
                    NULLIF(COUNT(*), 0)) * 100,
                    2
                ) as satisfaction_rate,
                COUNT(CASE WHEN DATE(created_at) = DATE('now') THEN 1 END) as today_count
            FROM feedback
            WHERE rating IS NOT NULL
        ''')
        stats_row = cursor.fetchone()
        stats = {
            'average_rating': stats_row[0],
            'total_feedback': stats_row[1],
            'satisfaction_rate': stats_row[2],
            'today_count': stats_row[3]
        }

        # Get rating distribution
        cursor.execute('''
            SELECT rating, COUNT(*) as count
            FROM feedback
            WHERE rating IS NOT NULL
            GROUP BY rating
            ORDER BY rating
        ''')
        ratings = [{'rating': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Get category distribution
        cursor.execute('''
            SELECT 
                COALESCE(category, 'General') as category,
                COUNT(*) as count
            FROM feedback
            GROUP BY category
            ORDER BY count DESC
        ''')
        categories = [{'name': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Get feedback entries with user information
        cursor.execute('''
            SELECT f.id, f.idno, u.firstname, u.lastname, f.rating, f.comment,
                   f.category, datetime(f.created_at) as created_at, u.course, u.year_level
            FROM feedback f
            JOIN users u ON f.idno = u.idNO
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?
        ''', (per_page, (page - 1) * per_page))

        feedbacks = [
            {
                'id': row[0],
                'idno': row[1],
                'student_name': f"{row[2]} {row[3]}".strip(),
                'rating': row[4],
                'comment': row[5],
                'category': row[6] or 'General',
                'created_at': row[7],
                'course': row[8],
                'year_level': row[9]
            }
            for row in cursor.fetchall()
        ]

        # Get total count for pagination
        cursor.execute('SELECT COUNT(*) FROM feedback')
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + per_page - 1) // per_page

        conn.close()

        return render_template('admin_feedback.html',
                             feedbacks=feedbacks,
                             stats=stats,
                             categories=categories,
                             ratings=ratings,
                             page=page,
                             total_pages=total_pages,
                             has_prev=page > 1,
                             has_next=page < total_pages)

    except Exception as e:
        print(f"Error in admin_feedback route: {e}")
        if 'conn' in locals():
            conn.close()
        return render_template('admin_feedback.html',
                             feedbacks=[],
                             stats={'average_rating': 0.0, 'total_feedback': 0, 'satisfaction_rate': 0.0, 'today_count': 0},
                             categories=[],
                             ratings=[],
                             page=1,
                             total_pages=1,
                             has_prev=False,
                             has_next=False,
                             error="An error occurred while loading the feedback page.")

@app.route('/admin/feedback/export')
@admin_required
def export_feedback():
    try:
        # Get filter parameters
        rating = request.args.get('rating')
        category = request.args.get('category')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Query with filters
        query = '''
            SELECT f.idno, u.firstname, u.lastname, f.rating, f.comment,
                   f.category, f.created_at, r.date, r.time
            FROM feedback f
            JOIN users u ON f.idno = u.idNO
            LEFT JOIN reservations r ON f.session_id = r.id
            WHERE 1=1
        '''
        params = []

        if rating:
            query += ' AND f.rating = ?'
            params.append(rating)
        if category:
            query += ' AND f.category = ?'
            params.append(category)
        if start_date and end_date:
            query += ' AND f.created_at BETWEEN ? AND ?'
            params.extend([start_date, end_date])

        query += ' ORDER BY f.created_at DESC'
        
        cursor.execute(query, params)
        feedbacks = cursor.fetchall()
        conn.close()

        # Create CSV in memory
        output = BytesIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID Number', 'Student Name', 'Rating', 'Comment', 
                        'Category', 'Created At', 'Session Date', 'Session Time'])
        
        # Write datass
        for row in feedbacks:
            writer.writerow([
                row[0],  # ID Number
                f"{row[1]} {row[2]}",  # Student Name
                row[3],  # Rating
                row[4],  # Comment
                row[5],  # Category
                row[6],  # Created At
                row[7],  # Session Date
                row[8]   # Session Time
            ])
        
        # Prepare response
        output.seek(0)
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'feedback_report_{datetime.now().strftime("%Y%m%d")}.csv'
        )

    except Exception as e:
        flash(f'Error exporting feedback: {str(e)}', 'error')
        return redirect(url_for('admin_feedback'))

@app.route('/admin/leaderboard')
@admin_required
def admin_leaderboard():
    # Get filter parameters
    course = request.args.get('course')
    year_level = request.args.get('year_level')
    period = request.args.get('period', 'all')  # all, monthly, weekly
    page = request.args.get('page', 1, type=int)
    per_page = 10

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Base query for achievements and leaderboard
    base_query = '''
        SELECT 
            u.idNO,
            u.firstname,
            u.lastname,
            u.course,
            u.year_level,
            COUNT(r.id) as total_sessions,
            COUNT(DISTINCT r.date) as unique_days,
            AVG(CASE 
                WHEN f.rating IS NOT NULL THEN f.rating 
                ELSE NULL 
            END) as avg_rating
        FROM users u
        LEFT JOIN reservations r ON u.idNO = r.idno
        LEFT JOIN feedback f ON r.id = f.session_id
        WHERE u.role != 'admin'
    '''
    params = []

    # Add period filter
    if period == 'monthly':
        base_query += " AND r.date >= date('now', 'start of month')"
    elif period == 'weekly':
        base_query += " AND r.date >= date('now', '-7 days')"

    # Add other filters
    if course:
        base_query += ' AND u.course = ?'
        params.append(course)
    if year_level:
        base_query += ' AND u.year_level = ?'
        params.append(year_level)

    # Group by and order
    base_query += '''
        GROUP BY u.idNO, u.firstname, u.lastname, u.course, u.year_level
        HAVING total_sessions > 0
        ORDER BY total_sessions DESC, avg_rating DESC
    '''

    # Get achievements
    cursor.execute(f'''
        WITH RankedUsers AS ({base_query})
        SELECT 
            (SELECT idNO || '|' || firstname || ' ' || lastname || '|' || total_sessions 
             FROM RankedUsers ORDER BY total_sessions DESC LIMIT 1) as most_sessions,
            (SELECT idNO || '|' || firstname || ' ' || lastname || '|' || avg_rating 
             FROM RankedUsers WHERE avg_rating IS NOT NULL ORDER BY avg_rating DESC LIMIT 1) as highest_rated,
            (SELECT idNO || '|' || firstname || ' ' || lastname || '|' || unique_days 
             FROM RankedUsers ORDER BY unique_days DESC LIMIT 1) as most_consistent
    ''', params)
    
    achievement_row = cursor.fetchone()
    achievements = {
        'most_sessions': {'student': 'No data', 'count': 0},
        'highest_rated': {'student': 'No data', 'rating': 0},
        'most_consistent': {'student': 'No data', 'days': 0}
    }
    
    if achievement_row[0]:
        idno, name, count = achievement_row[0].split('|')
        achievements['most_sessions'] = {'student': name, 'count': int(count)}
    if achievement_row[1]:
        idno, name, rating = achievement_row[1].split('|')
        achievements['highest_rated'] = {'student': name, 'rating': float(rating)}
    if achievement_row[2]:
        idno, name, days = achievement_row[2].split('|')
        achievements['most_consistent'] = {'student': name, 'days': int(days)}

    # Get course statistics
    cursor.execute('''
        SELECT 
            u.course,
            COUNT(DISTINCT u.idNO) as total_students,
            COUNT(r.id) as total_sessions,
            AVG(CASE WHEN f.rating IS NOT NULL THEN f.rating ELSE NULL END) as avg_rating
        FROM users u
        LEFT JOIN reservations r ON u.idNO = r.idno
        LEFT JOIN feedback f ON r.id = f.session_id
        WHERE u.role != 'admin' AND u.course IS NOT NULL
        GROUP BY u.course
        HAVING total_sessions > 0
        ORDER BY total_sessions DESC
    ''')
    course_stats = cursor.fetchall()

    # Get total count for pagination
    count_query = f"SELECT COUNT(*) FROM ({base_query})"
    cursor.execute(count_query, params)
    total_items = cursor.fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Add pagination to base query
    query = base_query + ' LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    # Get leaderboard data
    cursor.execute(query, params)
    leaderboard_data = cursor.fetchall()
    leaderboard = []
    for rank, row in enumerate(leaderboard_data, start=1 + (page - 1) * per_page):
        leaderboard.append({
            'rank': rank,
            'idno': row[0],
            'name': f"{row[1]} {row[2]}",
            'course': row[3] or 'Not specified',
            'year_level': row[4] or 'Not specified',
            'total_sessions': row[5],
            'unique_days': row[6],
            'avg_rating': f"{row[7]:.1f}" if row[7] else 'N/A'
        })

    # Get available courses and year levels for filters
    cursor.execute('SELECT DISTINCT course FROM users WHERE course IS NOT NULL')
    courses = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT year_level FROM users WHERE year_level IS NOT NULL')
    year_levels = [row[0] for row in cursor.fetchall()]

    conn.close()

    return render_template('admin_leaderboard.html',
                         achievements=achievements,
                         course_stats=course_stats,
                         leaderboard=leaderboard,
                         courses=courses,
                         year_levels=year_levels,
                         page=page,
                         total_pages=total_pages,
                         has_prev=page > 1,
                         has_next=page < total_pages,
                         current_course=course,
                         current_year=year_level,
                         current_period=period)

@app.route('/admin/leaderboard/export')
@admin_required
def export_leaderboard():
    course = request.args.get('course')
    year_level = request.args.get('year_level')
    period = request.args.get('period', 'all')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Base query for leaderboard data
    query = '''
        SELECT 
            u.idNO,
            u.firstname || ' ' || u.lastname as student_name,
            u.course,
            u.year_level,
            COUNT(r.id) as total_sessions,
            COUNT(DISTINCT r.date) as unique_days,
            AVG(CASE WHEN f.rating IS NOT NULL THEN f.rating ELSE NULL END) as avg_rating
        FROM users u
        LEFT JOIN reservations r ON u.idNO = r.idno
        LEFT JOIN feedback f ON r.id = f.session_id
        WHERE u.role != 'admin'
    '''
    params = []

    # Add filters
    if period == 'monthly':
        query += " AND r.date >= date('now', 'start of month')"
    elif period == 'weekly':
        query += " AND r.date >= date('now', '-7 days')"
    if course:
        query += ' AND u.course = ?'
        params.append(course)
    if year_level:
        query += ' AND u.year_level = ?'
        params.append(year_level)

    query += '''
        GROUP BY u.idNO, u.firstname, u.lastname, u.course, u.year_level
        HAVING total_sessions > 0
        ORDER BY total_sessions DESC, avg_rating DESC
    '''

    cursor.execute(query, params)
    data = cursor.fetchall()
    conn.close()

    # Create CSV in memory
    output = BytesIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Rank', 'ID Number', 'Student Name', 'Course', 'Year Level', 
                    'Total Sessions', 'Active Days', 'Average Rating'])
    
    # Write data
    for rank, row in enumerate(data, 1):
        writer.writerow([
            rank,
            row[0],  # ID Number
            row[1],  # Student Name
            row[2] or 'Not specified',  # Course
            row[3] or 'Not specified',  # Year Level
            row[4],  # Total Sessions
            row[5],  # Active Days
            f"{row[6]:.1f}" if row[6] else 'N/A'  # Average Rating
        ])

    # Prepare response
    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'sitin_leaderboard_{datetime.now().strftime("%Y%m%d")}.csv'
    )

# Add the delete student route after the edit_student route
@app.route('/admin/student/delete/<string:idno>', methods=['POST'])
@admin_required
def delete_student(idno):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # First check if student exists
        cursor.execute('SELECT idNO FROM users WHERE idNO = ?', (idno,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Student not found'}), 404

        # Delete student's reservations first (due to foreign key constraints)
        cursor.execute('DELETE FROM reservations WHERE idno = ?', (idno,))
        
        # Delete student's feedback (due to foreign key constraints)
        cursor.execute('DELETE FROM feedback WHERE idno = ?', (idno,))
        
        # Delete the student
        cursor.execute('DELETE FROM users WHERE idNO = ?', (idno,))
        
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Student deleted successfully'
        })

    except Exception as e:
        print(f"Error deleting student: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error occurred while deleting student'
        }), 500

@app.route('/submit-sitin-report', methods=['POST'])
def submit_sitin_report():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401

    try:
        data = request.get_json()
        record_id = data.get('record_id')
        message = data.get('message')

        if not record_id or not message:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # First verify that the record exists and belongs to the current user
        cursor.execute('''
            SELECT r.id 
            FROM reservations r
            JOIN users u ON r.idno = u.idNO
            WHERE r.id = ? AND u.username = ?
        ''', (record_id, session['username']))

        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Record not found or unauthorized'}), 404

        # Add the report to the database
        cursor.execute('''
            INSERT INTO feedback (idno, session_id, comment, category, created_at)
            SELECT u.idNO, ?, ?, 'sit-in report', datetime('now')
            FROM users u
            WHERE u.username = ?
        ''', (record_id, message, session['username']))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Report submitted successfully'
        })

    except Exception as e:
        print(f"Error submitting report: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while submitting the report'
        }), 500

@app.route('/admin/sitin-records/reply', methods=['POST'])
@admin_required
def reply_to_record():
    try:
        data = request.get_json()
        record_id = data.get('record_id')
        message = data.get('message')

        if not record_id or not message:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Add the reply to the feedback table
        cursor.execute('''
            INSERT INTO feedback (session_id, comment, category, created_at)
            VALUES (?, ?, 'admin-reply', datetime('now'))
        ''', (record_id, message))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Reply sent successfully'
        })

    except Exception as e:
        print(f"Error sending reply: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error occurred while sending reply'
        }), 500

@app.route('/admin/sitin-records/delete/<int:record_id>', methods=['POST'])
@admin_required
def delete_sitin_record(record_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # First delete associated feedback
        cursor.execute('DELETE FROM feedback WHERE session_id = ?', (record_id,))
        
        # Then delete the record
        cursor.execute('DELETE FROM reservations WHERE id = ?', (record_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'message': 'Record not found'}), 404

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Record deleted successfully'
        })

    except Exception as e:
        print(f"Error deleting record: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error occurred while deleting record'
        }), 500

@app.route('/delete-schedule/<string:edp_code>', methods=['POST'])
@admin_required
def delete_schedule_by_edp(edp_code):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # First verify if the schedule exists
        cursor.execute('SELECT * FROM lab_schedules WHERE edp_code = ?', (edp_code,))
        schedule = cursor.fetchone()
        
        if not schedule:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Schedule not found'
            }), 404

        # Delete the schedule
        cursor.execute('DELETE FROM lab_schedules WHERE edp_code = ?', (edp_code,))
        
        # Check if any rows were affected
        if cursor.rowcount > 0:
            conn.commit()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Schedule deleted successfully'
            })
        else:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Failed to delete schedule'
            }), 500

    except Exception as e:
        print(f"Error deleting schedule: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({
            'success': False,
            'message': f'Error occurred while deleting schedule: {str(e)}'
        }), 500

@app.route('/admin/schedule/delete/<int:schedule_id>', methods=['POST'])
@admin_required
def delete_lab_schedule(schedule_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # First verify if the schedule exists
        cursor.execute('SELECT * FROM lab_schedules WHERE id = ?', (schedule_id,))
        schedule = cursor.fetchone()
        
        if not schedule:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Schedule not found'
            }), 404

        # Delete the schedule
        cursor.execute('DELETE FROM lab_schedules WHERE id = ?', (schedule_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Schedule deleted successfully'
        })

    except Exception as e:
        print(f"Error deleting schedule: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({
            'success': False,
            'message': 'Error occurred while deleting schedule'
        }), 500

@app.route('/admin/search-students')
@admin_required
def search_students():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify([])

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Search by ID or name (first name or last name)
        cursor.execute('''
            SELECT idNO, firstname, lastname, course, year_level
            FROM users
            WHERE role != 'admin'
            AND (
                idNO LIKE ? 
                OR LOWER(firstname) LIKE LOWER(?)
                OR LOWER(lastname) LIKE LOWER(?)
            )
            ORDER BY lastname, firstname
            LIMIT 10
        ''', (f'%{query}%', f'%{query}%', f'%{query}%'))

        students = [
            {
                'idno': row[0],
                'firstname': row[1],
                'lastname': row[2],
                'course': row[3],
                'year_level': row[4]
            }
            for row in cursor.fetchall()
        ]

        conn.close()
        return jsonify(students)

    except Exception as e:
        print(f"Error searching students: {e}")
        return jsonify([])

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401

    try:
        data = request.get_json()
        rating = data.get('rating')
        category = data.get('category')
        message = data.get('feedback_message')

        if not all([rating, category, message]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Get user's ID number
        cursor.execute('SELECT idNO FROM users WHERE username = ?', (session['username'],))
        user_data = cursor.fetchone()

        if not user_data:
            conn.close()
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Insert the feedback
        cursor.execute('''
            INSERT INTO feedback (idno, rating, comment, category, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        ''', (user_data[0], rating, message, category))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully'
        })

    except Exception as e:
        print(f"Error submitting feedback: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while submitting feedback'
        }), 500

@app.route('/feed-reports')
@admin_required
def feed_reports():
    try:
        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        per_page = 10

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Get feedback with pagination and user information
        cursor.execute('''
            SELECT 
                f.id,
                f.rating,
                f.comment,
                f.category,
                datetime(f.created_at) as created_at,
                u.firstname,
                u.lastname,
                u.idNO as idno,
                u.course,
                u.year_level,
                u.email
            FROM feedback f
            JOIN users u ON f.idno = u.idNO
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?
        ''', (per_page, (page - 1) * per_page))
        
        feedbacks = []
        for row in cursor.fetchall():
            feedbacks.append({
                'id': row[0],
                'rating': row[1],
                'comment': row[2],
                'category': row[3] or 'General',
                'created_at': row[4].replace('T', ' '),
                'student_name': f"{row[5]} {row[6]}".strip(),
                'idno': row[7],
                'course': row[8],
                'year_level': row[9],
                'email': row[10]
            })

        # Get total pages for pagination
        cursor.execute('SELECT COUNT(*) FROM feedback')
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + per_page - 1) // per_page

        conn.close()
        return render_template('admin_feedback.html', 
                             feedbacks=feedbacks,
                             current_page=page,
                             total_pages=total_pages,
                             has_prev=page > 1,
                             has_next=page < total_pages)

    except Exception as e:
        print(f"Error in feed_reports route: {e}")
        if 'conn' in locals():
            conn.close()
        return render_template('admin_feedback.html',
                             feedbacks=[],
                             current_page=1,
                             total_pages=1,
                             has_prev=False,
                             has_next=False,
                             error="An error occurred while loading the feedback page.")

if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(debug=True)