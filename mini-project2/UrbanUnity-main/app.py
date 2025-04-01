import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
import cloudinary.api

# Cloudinary configuration
cloudinary.config( 
  cloud_name = "dsno14dv8",  
  api_key = "493755698581822",  
  api_secret = "QGuxpP9GMQ6XYmI_04FeAg3v0VQ"  
)

app = Flask(__name__)
app.secret_key = '123456'  # Secret key for session management

# Configure Upload Folder
#UPLOAD_FOLDER = 'static/uploads'
#if not os.path.exists(UPLOAD_FOLDER):
#    os.makedirs(UPLOAD_FOLDER)  # Create folder if not exists
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",  
        user="raisen",
        password="123456",
        database="urbanunity"
    )

# Home route
@app.route('/')
def home():
    return render_template('landing.html')

# Citizen Authentication Routes
@app.route('/citizen-login', methods=['GET', 'POST'])
def citizen_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()
        
        # Check if the username exists
        cursor.execute("SELECT id, password FROM citizens WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:
            user_id, hashed_password = user
            # Verify the hashed password
            if check_password_hash(hashed_password, password):
                session['user_id'] = user_id  # Store user ID
                session['username'] = username  # Store username
                flash(f"Welcome, {username}!", "success")
                cursor.close()
                db.close()
                return redirect(url_for('cdashboard'))  # Redirect to dashboard
            else:
                flash("Incorrect password! Please try again.", "danger")
        else:
            flash("Username does not exist! Please sign up first.", "warning")
        
        cursor.close()
        db.close()

    return render_template('clogin3.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first-name']
        last_name = request.form['last-name']
        phone_number = request.form['phone']
        city = request.form['city']
        username = request.form['username']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM citizens WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            db.close()
            return render_template('clogin2.html', error="Username already exists! Try another one.")

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        # Insert into the database
        try:
            cursor.execute("""
                INSERT INTO citizens (first_name, last_name, phone_number, city, username, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, phone_number, city, username, hashed_password))
            db.commit()
            flash("Signup successful! Please log in.", "success")
            cursor.close()
            db.close()
            return redirect(url_for('citizen_login'))
        except mysql.connector.Error as err:
            cursor.close()
            db.close()
            return render_template('clogin2.html', error=f"Database error: {err}")

    return render_template('clogin2.html')

@app.route('/citizen-dashboard')
def cdashboard():
    if 'user_id' not in session:  # Check if user is logged in
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
    
    username = session['username']
    
    db = get_db_connection()
    cursor = db.cursor()
    
    # Fetch grievances of logged-in user
    cursor.execute("SELECT id, location, description, status, submitted_at FROM grievances WHERE user_id = %s", (session['user_id'],))
    grievances = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('cdashboard.html', username=username, grievances=grievances)

@app.route('/track-grievance')
def track_grievance():
    if 'user_id' not in session:  # Check if user is logged in
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
    
    username = session['username']
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Fetch grievances of logged-in user
    cursor.execute("SELECT id, location, description, status, submitted_at, photo_path FROM grievances WHERE user_id = %s", (session['user_id'],))
    grievances = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('viewstatus.html', username=username, grievances=grievances)

# Admin Routes
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        government_id = request.form['government_id']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute("SELECT id, password FROM government WHERE government_id = %s", (government_id,))
            admin = cursor.fetchone()

            if admin is None:
                flash("Government ID does not exist!", "warning")
                return render_template('alogin.html')

            admin_id, hashed_password = admin
            if check_password_hash(hashed_password, password):
                session['admin_id'] = admin_id
                session['government_id'] = government_id
                flash(f"Welcome, {government_id}!", "success")
                return redirect(url_for('manage_issues'))
            else:
                flash("Incorrect password! Please try again.", "danger")
        
        finally:
            cursor.close()
            db.close()

    return render_template('alogin.html')


@app.route('/manage-issues')
def manage_issues():
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    location_filter = request.args.get('location', 'all')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Base query
    query = "SELECT * FROM grievances"
    params = []
    
    # Apply filters
    conditions = []
    if status_filter != 'all':
        conditions.append("status = %s")
        params.append(status_filter)
    
    if location_filter != 'all':
        conditions.append("location LIKE %s")
        params.append(f"%{location_filter}%")
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    # Execute query
    cursor.execute(query, params)
    grievances = cursor.fetchall()

    # Get tasks that need verification (status = 'Resolved' AND needs_verification = 1)
    cursor.execute("SELECT * FROM grievances WHERE status = 'Resolved' AND needs_verification = 1")
    Resolved_tasks = cursor.fetchall()

    # Count grievances by status for pie chart
    cursor.execute("SELECT status, COUNT(*) as count FROM grievances GROUP BY status")
    status_counts = {row['status']: row['count'] for row in cursor.fetchall()}

    # Fetch all contractors for dropdown
    cursor.execute("SELECT id, services_provided FROM contractors")
    contractors = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('manageissues.html', 
                           grievances=grievances,
                           Resolved_tasks=Resolved_tasks,
                           status_counts=status_counts, 
                           contractors=contractors,
                           status_filter=status_filter,
                           location_filter=location_filter)

@app.route('/assign_contractor', methods=['POST'])
def assign_contractor():
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))

    grievance_id = request.form.get('grievance_id')
    contractor_id = request.form.get('contractor_id')

    if grievance_id and contractor_id:
        db = get_db_connection()
        cursor = db.cursor()
        # Change status to "In Progress" when assigning a contractor
        cursor.execute("UPDATE grievances SET contractor_id = %s, status = 'In Progress' WHERE id = %s", 
                      (contractor_id, grievance_id))
        db.commit()
        cursor.close()
        db.close()
        flash("Contractor assigned successfully! Status updated to In Progress.", "success")

    return redirect(url_for('manage_issues'))

@app.route('/verify_task', methods=['POST'])
def verify_task():
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))
        
    task_id = request.form.get('task_id')
    
    if task_id:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Change status to 'completed'
        cursor.execute("""
            UPDATE grievances 
            SET needs_verification = 0, 
                verified_by = %s, 
                verified_at = NOW(),
                status = 'completed' 
            WHERE id = %s
        """, (session['admin_id'], task_id))
        db.commit()
        cursor.close()
        db.close()
        flash("Task verified successfully!", "success")
        
    return redirect(url_for('manage_issues'))

@app.route('/request_revision', methods=['POST'])
def request_revision():
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))
        
    task_id = request.form.get('task_id')
    
    if task_id:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Set the status back to "In Progress" and add a revision note
        cursor.execute("""
            UPDATE grievances 
            SET status = 'In Progress', 
                revision_requested = 1,
                needs_verification = 0 
            WHERE id = %s
        """, (task_id,))
        db.commit()
        cursor.close()
        db.close()
        flash("Revision requested. Task status changed to In Progress.", "warning")
        
    return redirect(url_for('manage_issues'))

@app.route('/update_status/<int:grievance_id>', methods=['POST'])
def update_status(grievance_id):
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))
        
    new_status = request.form.get('status')
    if new_status:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("UPDATE grievances SET status = %s WHERE id = %s", 
                      (new_status, grievance_id))
        db.commit()
        cursor.close()
        db.close()
        flash(f"Status updated to {new_status}!", "success")
        
    return redirect(url_for('manage_issues'))




# Contractor Routes
@app.route('/contractor-login', methods=['GET', 'POST'])
def contractor_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()

        # Check if the contractor exists
        cursor.execute("SELECT id, password FROM contractors WHERE username = %s", (username,))
        contractor = cursor.fetchone()
        
        if contractor:
            contractor_id, hashed_password = contractor
            if check_password_hash(hashed_password, password):
                session['contractor_id'] = contractor_id
                session['contractor_username'] = username
                flash(f"Welcome, {username}!", "success")
                cursor.close()
                db.close()
                return redirect(url_for('contractor_dashboard'))
            else:
                flash("Incorrect password! Please try again.", "danger")
        else:
            flash("Username does not exist! Please sign up first.", "warning")
        
        cursor.close()
        db.close()

    return render_template('blogin.html')

@app.route('/contractor-dashboard')
def contractor_dashboard():
    if 'contractor_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('contractor_login'))
    
    username = session['contractor_username']
    contractor_id = session['contractor_id']
    
    # Get filter parameters
    status_filter = request.args.get('status_filter', 'all')
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Base query for assigned tasks
    query = "SELECT * FROM grievances WHERE contractor_id = %s"
    params = [contractor_id]
    
    # Apply status filter
    if status_filter != 'all':
        query += " AND status = %s"
        params.append(status_filter)
        
    # Execute query
    cursor.execute(query, params)
    tasks = cursor.fetchall()
    
    # Find tasks that need revision
    cursor.execute("""
        SELECT * FROM grievances 
        WHERE contractor_id = %s AND status = 'In Progress' AND revision_requested = 1
    """, (contractor_id,))
    revision_requests = cursor.fetchall()
    
    # Count tasks by status
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as pending_verification,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
        FROM grievances
        WHERE contractor_id = %s
    """, (contractor_id,))
    counts = cursor.fetchone()
    
    # Get completed tasks
    cursor.execute("SELECT * FROM grievances WHERE contractor_id = %s AND status = 'completed'", (contractor_id,))
    completed_tasks_list = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('contractor.html', 
                          username=username, 
                          tasks=tasks, 
                          completed_tasks_list=completed_tasks_list,
                          revision_requests=revision_requests,
                          assigned_tasks=counts['total'],
                          in_progress_tasks=counts['in_progress'],
                          pending_verification_tasks=counts['pending_verification'],
                          completed_tasks=counts['completed'],
                          status_filter=status_filter)

@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    if 'contractor_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('contractor_login'))
        
    task_id = request.form.get('task_id')
    new_status = request.form.get('status')
    
    if task_id and new_status:
        db = get_db_connection()
        cursor = db.cursor()
        
        # If contractor is marking as "Resolved", set needs_verification flag
        if new_status == 'Resolved':
            cursor.execute("""
                UPDATE grievances 
                SET status = 'Resolved', 
                    needs_verification = 1,
                    revision_requested = 0,
                    completed_at = NOW() 
                WHERE id = %s AND contractor_id = %s
            """, (task_id, session['contractor_id']))
        else:
            cursor.execute("UPDATE grievances SET status = %s WHERE id = %s AND contractor_id = %s", 
                        (new_status, task_id, session['contractor_id']))
        
        db.commit()
        cursor.close()
        db.close()
        
        if new_status == 'Resolved':
            flash("Task marked as Resolved and sent for admin verification!", "success")
        else:
            flash(f"Task marked as {new_status}!", "success")
        
    return redirect(url_for('contractor_dashboard'))

# Grievance Management Routes
@app.route('/report-issue')
def report_issue():
    if 'user_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
    
    return render_template('report1.html')

@app.route('/submit-grievance', methods=['POST'])
def submit_grievance():
    if 'user_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))

    user_id = session['user_id']
    location = request.form.get('location')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    description = request.form.get('description')
    phone = request.form.get('phone')
    photo = request.files.get('photo')

    if not all([location, latitude, longitude, description, phone]):
        flash("All fields are required!", "danger")
        return redirect(url_for('report_issue'))

    # Upload image to Cloudinary
    photo_url = None
    if photo and photo.filename:
        try:
            upload_result = cloudinary.uploader.upload(photo)
            photo_url = upload_result['secure_url']  # Get the uploaded image URL
        except Exception as e:
            flash(f"Error uploading image: {str(e)}", "danger")
            # Continue without the photo if upload fails

    db = get_db_connection()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO grievances (user_id, location, latitude, longitude, description, phone, photo_path, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, location, latitude, longitude, description, phone, photo_url, 'pending'))
        db.commit()
        flash("Grievance submitted successfully!", "success")
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('cdashboard'))

# Authentication Management
@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)