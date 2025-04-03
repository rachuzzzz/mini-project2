import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
import cloudinary.api
from bot import chatbot_api


# Cloudinary configuration
cloudinary.config( 
  cloud_name = "dsno14dv8",  
  api_key = "493755698581822",  
  api_secret = "QGuxpP9GMQ6XYmI_04FeAg3v0VQ"  
)

app = Flask(__name__)
app.secret_key = '123456'  # Secret key for session management
app.register_blueprint(chatbot_api)

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
    # Check for existing sessions across different user types
    # No need to redirect if already logged in - template will handle display logic
    
    errors = {}
    username = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Form validation
        if not username:
            errors['username'] = 'Username is required'
        if not password:
            errors['password'] = 'Password is required'
            
        if errors:
            return render_template('clogin3.html', username=username, errors=errors)

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        try:
            # Check if the username exists
            cursor.execute("SELECT id, username, password FROM citizens WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                flash("Username not found. Please check your username or sign up.", "warning")
                return render_template('clogin3.html', username=username)
            
            # Verify the hashed password
            if check_password_hash(user['password'], password):
                # Clear any existing sessions before setting new one
                session.clear()
                
                # Set new session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = 'citizen'  # Add role for easier identification
                
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('cdashboard'))
            else:
                flash("Incorrect password. Please try again.", "danger")
                return render_template('clogin3.html', username=username)
                
        except mysql.connector.Error as err:
            app.logger.error(f"Database error during login: {str(err)}")
            flash("A system error occurred. Please try again later.", "danger")
            return render_template('clogin3.html', username=username)
            
        finally:
            cursor.close()
            db.close()

    # GET request or failed POST with preserved username
    return render_template('clogin3.html', username=username, errors=errors)

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
    if 'user_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
    
    status_filter = request.args.get('status', 'all')
    date_filter = request.args.get('date', 'all')
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Base query
    query = """
        SELECT id, location, description, status, submitted_at, photo_path 
        FROM grievances 
        WHERE user_id = %s
    """
    params = [session['user_id']]
    
    # Apply status filter
    if status_filter != 'all':
        query += " AND status = %s"
        params.append(status_filter)
    
    # Apply date filter
    if date_filter != 'all':
        if date_filter == 'week':
            query += " AND submitted_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
        elif date_filter == 'month':
            query += " AND submitted_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"
        elif date_filter == 'year':
            query += " AND submitted_at >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)"
    
    query += " ORDER BY submitted_at DESC"
    
    cursor.execute(query, params)
    grievances = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('viewstatus.html', grievances=grievances)

# Admin Routes
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    # Check if user is already logged in as citizen or contractor
    # No need to redirect - template will handle display logic
    
    if request.method == 'POST':
        government_id = request.form['government_id']
        password = request.form['password']

        if not government_id or not password:
            flash("Both Government ID and password are required", "danger")
            return render_template('alogin.html')

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
                # Clear any existing sessions before setting new one
                session.clear()
                
                # Set new session
                session['admin_id'] = admin_id
                session['government_id'] = government_id
                session['role'] = 'admin'  # Add role for easier identification
                
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
    status_filter = request.args.get('status_filter', 'all')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Base query
    query = "SELECT * FROM grievances"
    params = []
    
    # Apply filters
    if status_filter != 'all':
        query += " WHERE status = %s"
        params.append(status_filter)
    
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
                           status_filter=status_filter)

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
    errors = {}
    username = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Basic validation
        if not username:
            errors['username'] = 'Username is required'
        if not password:
            errors['password'] = 'Password is required'
            
        if errors:
            return render_template('blogin.html', username=username, errors=errors)

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        try:
            # Check contractor exists
            cursor.execute("SELECT id, username, password FROM contractors WHERE username = %s", (username,))
            contractor = cursor.fetchone()
            
            if not contractor:
                flash("Username not found.", "warning")
                return render_template('blogin.html', username=username)
            
            # Verify password
            if check_password_hash(contractor['password'], password):
                session.clear()
                session['contractor_id'] = contractor['id']
                session['contractor_username'] = contractor['username']
                session['role'] = 'contractor'
                flash(f"Welcome, {contractor['username']}!", "success")
                return redirect(url_for('contractor_dashboard'))
            else:
                flash("Incorrect password.", "danger")
                return render_template('blogin.html', username=username)
                
        except mysql.connector.Error as err:
            app.logger.error(f"Database error: {err}")
            flash("System error. Please try again.", "danger")
            return render_template('blogin.html', username=username)
            
        finally:
            cursor.close()
            db.close()

    return render_template('blogin.html', username=username, errors=errors)

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
    completion_proof = request.files.get('completion_proof')

    if not task_id or not new_status:
        flash("Missing required data!", "danger")
        return redirect(url_for('contractor_dashboard'))

    db = get_db_connection()
    cursor = db.cursor()

    try:
        # Upload completion proof to Cloudinary if provided
        proof_url = None
        if completion_proof and completion_proof.filename:
            upload_result = cloudinary.uploader.upload(completion_proof)
            proof_url = upload_result['secure_url']

        if new_status == 'Resolved':
            cursor.execute("""
                UPDATE grievances 
                SET status = 'Resolved', 
                    needs_verification = 1,
                    completion_proof_url = %s,
                    revision_requested = 0,
                    completed_at = NOW()
                WHERE id = %s AND contractor_id = %s
            """, (proof_url, task_id, session['contractor_id']))
        else:
            cursor.execute("""
                UPDATE grievances 
                SET status = %s 
                WHERE id = %s AND contractor_id = %s
            """, (new_status, task_id, session['contractor_id']))
        
        db.commit()
        flash("Task marked as Resolved and sent for admin verification!", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error updating task: {str(e)}", "danger")
    finally:
        cursor.close()
        db.close()

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
    photo = request.files.get('photo')

    if not all([location, latitude, longitude, description]):
        flash("All fields are required!", "danger")
        return redirect(url_for('report_issue'))
        
    # Fetch phone number from the citizen table instead of form input
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT phone_number FROM citizens WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    
    if not result:
        flash("Error retrieving user information!", "danger")
        cursor.close()
        db.close()
        return redirect(url_for('report_issue'))
        
    phone = result[0]  # Get phone number from database

    # Upload image to Cloudinary
    photo_url = None
    if photo and photo.filename:
        try:
            upload_result = cloudinary.uploader.upload(photo)
            photo_url = upload_result['secure_url']  # Get the uploaded image URL
        except Exception as e:
            flash(f"Error uploading image: {str(e)}", "danger")
            # Continue without the photo if upload fails

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

# Add these routes to app.py

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
        
    user_id = session['user_id']
    feedback_text = request.form.get('feedback_text')
    rating = request.form.get('rating')
    
    # Basic validation
    if not feedback_text:
        flash("Feedback text is required!", "danger")
        return redirect(url_for('view_feedback'))
    
    if rating:
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                flash("Rating must be between 1 and 5", "danger")
                return redirect(url_for('view_feedback'))
        except ValueError:
            flash("Rating must be a number", "danger")
            return redirect(url_for('view_feedback'))
    
    db = get_db_connection()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO feedback (user_id, feedback_text, rating)
            VALUES (%s, %s, %s)
        """, (user_id, feedback_text, rating))
        db.commit()
        flash("Thank you for your feedback!", "success")
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
    finally:
        cursor.close()
        db.close()
    
    return redirect(url_for('cdashboard'))

@app.route('/view-feedback')
def view_feedback():
    if 'user_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('citizen_login'))
    
    username = session['username']
    
    # Get user's past feedback
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT id, feedback_text, rating, submitted_at
        FROM feedback
        WHERE user_id = %s
        ORDER BY submitted_at DESC
    """, (session['user_id'],))
    
    user_feedback = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('feedback.html', username=username, user_feedback=user_feedback)

# Admin view for all feedback
@app.route('/admin-feedback')
def admin_feedback():
    if 'admin_id' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))
    
    # Get filter parameters
    rating_filter = request.args.get('rating', 'all')
    date_filter = request.args.get('date', 'all')
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Base query
    query = """
        SELECT f.id, f.feedback_text, f.rating, f.submitted_at, 
               c.username, c.first_name, c.last_name
        FROM feedback f
        JOIN citizens c ON f.user_id = c.id
    """
    
    params = []
    conditions = []
    
    # Apply filters
    if rating_filter != 'all':
        conditions.append("f.rating = %s")
        params.append(int(rating_filter))
    
    if date_filter != 'all':
        if date_filter == 'today':
            conditions.append("DATE(f.submitted_at) = CURDATE()")
        elif date_filter == 'week':
            conditions.append("f.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)")
        elif date_filter == 'month':
            conditions.append("f.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)")
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY f.submitted_at DESC"
    
    cursor.execute(query, params)
    all_feedback = cursor.fetchall()
    
    # Calculate statistics
    cursor.execute("""
        SELECT 
            COUNT(*) as total_count,
            AVG(rating) as avg_rating,
            SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_star,
            SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_star,
            SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_star,
            SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_star,
            SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
        FROM feedback
    """)
    
    stats = cursor.fetchone()
    
    cursor.close()
    db.close()
    
    return render_template(
        'feedbackview.html', 
        all_feedback=all_feedback, 
        stats=stats,
        rating_filter=rating_filter,
        date_filter=date_filter
    )

# Authentication Management
@app.route('/logout')
def logout():
    try:
        # Check if user is actually logged in before attempting logout
        if 'user_id' in session or 'admin_id' in session or 'contractor_id' in session:
            # Store the role for the success message
            role = session.get('role', 'user')
            
            # Clear all session data
            session.clear()
            
            # Success message
            flash(f"Logged out successfully!", "success")
        else:
            # User wasn't logged in
            flash("No active session to log out from.", "warning")
            
        return redirect(url_for('home'))
        
    except Exception as e:
        # Log the error
        app.logger.error(f"Error during logout: {str(e)}")
        
        # Clear session anyway as a precaution
        try:
            session.clear()
        except:
            pass
            
        # Inform the user
        flash("An error occurred during logout. Please try again or contact support if the issue persists.", "danger")
        return redirect(url_for('home'))

if __name__ == '__main__':
    # Certificate files path - we'll generate these
    cert_path = 'cert.pem'
    key_path = 'key.pem'
    
    # Check if certificate files exist, create them if not
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        # Generate self-signed certificate
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "Locality"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # 1 year validity
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Write private key
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        print(f"Generated self-signed certificate: {cert_path} and {key_path}")
    
    # Run with HTTPS
    app.run(
        debug=True,
        host='0.0.0.0',  # Allow access from all interfaces
        ssl_context=(cert_path, key_path)
    )