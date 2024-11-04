import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime
import face_recognition as fr
import cv2
import base64


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Ensure the "Images" and "Attendances" directories exist
os.makedirs("static/Images", exist_ok=True)
os.makedirs("Attendances", exist_ok=True)

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User model with roles
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Role: Teacher or Student
    status = db.Column(db.String(50), default='pending')  # New status column
    image_filename = db.Column(db.String(150), nullable=True)  # Add this line to store the image filename
     # Define relationship for enrollments
    enrollments = db.relationship('Enrollment', back_populates='student')  # Add this line

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        # Define relationships
    students = db.relationship('Enrollment', back_populates='class_enrolled', lazy=True)
    teacher = db.relationship('User', backref='classes')


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # Status: pending, approved, denied    

       # Define relationships
    student = db.relationship('User', back_populates='enrollments')  # Assuming User has a back_populates
    class_enrolled = db.relationship('Class', back_populates='students')  # Use back_populates for clarity

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default='Absent')  # Status: Present or Absent

    # Define relationships
    student = db.relationship('User')
    class_attended = db.relationship('Class')

# Function to capture a new image
def capture_new_image(image_name):
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    if ret:
        cv2.imwrite(f'Images/{image_name}.jpg', frame)
    cap.release()

# Function to encode faces
def encode_faces():
    encoded_data = {}
    for dirpath, dnames, fnames in os.walk("./Images"):
        for f in fnames:
            if f.endswith(".jpg") or f.endswith(".png"):
                face = fr.load_image_file(f"Images/{f}")
                encoding = fr.face_encodings(face)[0]
                encoded_data[f.split(".")[0]] = encoding
    return encoded_data

# Function to detect faces and record attendance
def detect_faces():
    faces = encode_faces()
    encoded_faces = list(faces.values())
    faces_name = list(faces.keys())
    video = cv2.VideoCapture(0)
    detected_faces_today = set()

    with open("detected_faces.txt", "a") as f:
        while True:
            ret, frame = video.read()
            if not ret:
                break

            face_locations = fr.face_locations(frame)
            unknown_face_encodings = fr.face_encodings(frame, face_locations)

            face_names = []
            for face_encoding in unknown_face_encodings:
                matches = fr.compare_faces(encoded_faces, face_encoding)
                name = "Unknown"
                if True in matches:
                    first_match_index = matches.index(True)
                    name = faces_name[first_match_index]
                face_names.append(name)

            now = datetime.datetime.now()
            timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")

            for (top, right, bottom, left), name in zip(face_locations, face_names):
                if name != "Unknown" and name not in detected_faces_today:
                    filename = f"{timestamp}_{name}.jpg"
                    filepath = os.path.join("Attendances", filename)
                    cv2.imwrite(filepath, frame[top:bottom, left:right])
                    detected_faces_today.add(name)
                    f.write(f"Attendance recorded for {name} at {timestamp}\n")
                    print(f"Attendance recorded for {name} at {timestamp}")

            for (top, right, bottom, left), name in zip(face_locations, face_names):
                cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
                cv2.putText(frame, name, (left, bottom), cv2.FONT_HERSHEY_SIMPLEX, 0.75, (255, 255, 255), 2)

            cv2.imshow('Video', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    video.release()
    cv2.destroyAllWindows()

  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Get the role from the form
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
        else:
            hashed_password = generate_password_hash(password)
            # Set status to 'pending' for teachers
            if role == 'Teacher':
                status = 'pending'
            else:
                status = 'approved'  # Automatically approve students
            
            new_user = User(username=username, password=hashed_password, role=role, status=status)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Your registration is pending approval.')

              # Redirect to the image capture page if the user is a student
            if role == 'Student':
                return redirect(url_for('capture_image', username=username))  # Redirect to capture image page
            
            # Do not log in the user if they are a teacher
            if role == 'Teacher':
                return redirect(url_for('login'))  # Redirect to the login page for teachers
            
            return redirect(url_for('login'))  # Redirect to login for other roles

    return render_template('register.html')

@app.route('/capture_image/<username>', methods=['GET', 'POST'])
def capture_image(username):
    if request.method == 'POST':
        # Capture the image and save it
        capture_new_image(username)  # Use the username as the image name
        flash('Image captured successfully! Please log in to continue.')
        return redirect(url_for('login'))  # Redirect to the login page

    return render_template('capture_image.html', username=username)  # Render the capture image page



@app.route('/save_image', methods=['POST'])
def save_image():
    data = request.get_json()
    image_data = data['image']
    username = data['username']

    # Process the image data
    image_data = image_data.split(',')[1]  # Remove the data URL part
    image_data = base64.b64decode(image_data)  # Decode the image data

    # Save the image
    image_path = f'static/Images/{username}.jpg'  # Ensure the path is correct
    with open(image_path, 'wb') as f:
        f.write(image_data)

    # Update the user's image filename in the database
    user = User.query.filter_by(username=username).first()
    if user:
        user.image_filename = f"{username}.jpg"  # Set the image filename
        db.session.commit()  # Save changes to the database

    return {'success': True}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log the user in
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'Teacher':
                if user.status == 'pending':
                    flash('Your account is pending approval by an admin. Please wait for approval before logging in.')
                    return redirect(url_for('login'))
                elif user.status == 'denied':
                    flash('Your account has been denied. Please contact admin for more information.')
                    return redirect(url_for('login'))
                return redirect(url_for('teacher_dashboard'))
            elif user.role == 'Student':
                return redirect(url_for('student_dashboard'))  # Redirect to the student dashboard
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')



@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! Your role is {current_user.role}. <a href="/logout">Logout</a>'

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# Role-based access control decorators
def admin_required(f):
    @wraps(f)  # Preserve the original function's name and docstring
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            flash('Access denied: Admins only.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Admin route
@app.route('/admin')
@admin_required
def admin_dashboard():
    all_users = User.query.all()
    pending_teachers = User.query.filter_by(role='Teacher', status='pending').all()
    approved_teachers = User.query.filter_by(role='Teacher', status='approved').all()
    students = User.query.filter_by(role='Student').all()
    
    return render_template('admin/admin_dashboard.html', 
                           all_users=all_users, 
                           pending_teachers=pending_teachers, 
                           approved_teachers=approved_teachers, 
                           students=students)

# Teacher route
# Function to require teacher access
def teacher_required(f):
    @wraps(f)  # Preserve the original function's name and docstring
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['Admin', 'Teacher']:
            flash('Access denied: Admins and Teachers only.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/teacher/dashboard')
@login_required
@teacher_required
def teacher_dashboard():
    # Get all classes taught by the current teacher
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher/teacher_dashboard.html', classes=classes)

@app.route('/teacher/create_class', methods=['POST'])
@login_required
@teacher_required
def create_class():
    class_name = request.form['class_name']
    new_class = Class(name=class_name, teacher_id=current_user.id)
    db.session.add(new_class)
    db.session.commit()
    flash('Class created successfully!')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/view_enrollments/<int:class_id>')
@login_required
@teacher_required
def view_enrollments(class_id):
    # Get the enrollments for the specified class
    enrollments = Enrollment.query.filter_by(class_id=class_id).all()
    class_obj = db.session.get(Class, class_id)  # Use Session.get()
    class_name = class_obj.name if class_obj else 'Class not found'  # Handle case where class is not found
    
    return render_template('teacher/view_enrollments.html', enrollments=enrollments, class_name=class_name)

@app.route('/teacher/update_enrollment/<int:enrollment_id>/<action>', methods=['POST'])
@login_required
@teacher_required
def update_enrollment(enrollment_id, action):
    enrollment = db.session.get(Enrollment, enrollment_id)  # Use Session.get()
    if enrollment:
        if action == 'approve':
            enrollment.status = 'Approved'
        elif action == 'deny':
            enrollment.status = 'Denied'
        
        try:
            db.session.commit()  # Commit the changes
            flash(f'Enrollment has been {action}d successfully!')
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash('An error occurred while updating the enrollment.')
            print(f'Error: {e}')  # Print the error for debugging
    else:
        flash('Enrollment not found.')
    return redirect(url_for('view_enrollments', class_id=enrollment.class_id))

@app.route('/teacher/mark_attendance/<int:class_id>', methods=['GET', 'POST'])
@login_required
@teacher_required
def mark_attendance(class_id):
    class_obj = Class.query.get(class_id)
    students = Enrollment.query.filter_by(class_id=class_id, status='Approved').all()  # Get approved students

    if request.method == 'POST':
        date_str = request.form['date']  # Get the date string from the form
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()  # Convert to a date object

        for student in students:
            status = request.form.get(f'student_{student.student_id}')  # Get attendance status from the form
            attendance_record = Attendance(student_id=student.student_id, class_id=class_id, date=date_obj, status=status)
            db.session.add(attendance_record)
        db.session.commit()
        flash('Attendance marked successfully!')
        return redirect(url_for('teacher_dashboard'))

    return render_template('teacher/mark_attendance.html', class_obj=class_obj, students=students)

@app.route('/teacher/capture_image', methods=['POST'])
@login_required
def teacher_capture_image():
    if current_user.role == 'Teacher':
        image_name = request.form['image_name']
        capture_new_image(image_name)  # Ensure this function is defined elsewhere
        flash('Image captured successfully!')
    else:
        flash('Access denied: Teachers only.')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/detect_faces')
@login_required
def start_face_detection():
    if current_user.role == 'Teacher':
        detect_faces()
        flash('Face detection started!')
    else:
        flash('Access denied: Teachers only.')
    return redirect(url_for('teacher_dashboard'))


@app.route('/student/dashboard')
@login_required
def student_dashboard():
    available_classes = Class.query.all()  # Get all available classes
    approved_classes = Class.query.join(Enrollment).filter(Enrollment.student_id == current_user.id, Enrollment.status == 'Approved').all()  # Get approved classes for the current student

    # Debugging: Check current user details
    print(f"Current user: {current_user.username}, Image filename: {current_user.image_filename}")

    # Create a list of dictionaries to hold class and teacher information
    approved_classes_with_teachers = []
    for cls in approved_classes:
        approved_classes_with_teachers.append({
            'class': cls,
            'teacher_name': cls.teacher.username if cls.teacher else 'No teacher assigned'
        })

    # Get pending enrollments for the current student
    pending_enrollments = Enrollment.query.filter_by(student_id=current_user.id, status='Pending').all()
    pending_class_ids = {enrollment.class_id for enrollment in pending_enrollments}

    # Create a set of approved class IDs for quick lookup
    approved_class_ids = {cls.id for cls in approved_classes}

    return render_template(
        'student/student_dashboard.html',
        available_classes=available_classes,
        approved_classes=approved_classes,
        pending_class_ids=pending_class_ids,
        approved_class_ids=approved_class_ids,
        image_filename=current_user.image_filename  # Pass the image filename to the template
    )


@app.route('/student/enroll/<int:class_id>', methods=['POST'])
@login_required
def enroll_in_class(class_id):
    # Check if the student is already enrolled
    existing_enrollment = Enrollment.query.filter_by(student_id=current_user.id, class_id=class_id).first()
    if existing_enrollment:
        flash('You are already enrolled in this class.')
    else:
        new_enrollment = Enrollment(student_id=current_user.id, class_id=class_id, status='Pending')
        db.session.add(new_enrollment)
        db.session.commit()
        flash('Enrollment request submitted successfully!')

    return redirect(url_for('student_dashboard'))

@app.route('/student/view_attendance')
@login_required
def view_attendance():
    attendances = Attendance.query.filter_by(student_id=current_user.id).all()
    return render_template('student/view_attendance.html', attendances=attendances)



# Admin route 
@app.route('/admin/approve_teacher/<int:user_id>')
@admin_required
def approve_teacher(user_id):
    user = User.query.get(user_id)
    if user and user.role == 'Teacher':
        user.status = 'approved'
        try:
            db.session.commit()
            flash(f'Teacher {user.username} has been approved.')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while approving the teacher.')
            print(e)  # Log the error for debugging
    else:
        flash('User not found or not a teacher.')
    return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard

# Admin route to deny teachers
@app.route('/admin/deny_teacher/<int:user_id>')
@admin_required
def deny_teacher(user_id):
    user = User.query.get(user_id)
    if user and user.role == 'Teacher':
        db.session.delete(user)  # Delete the user from the database
        db.session.commit()
        flash(f'Teacher {user.username} has been denied and removed from the database.')
    else:
        flash('User not found or not a teacher.')
    return redirect(url_for('admin_dashboard'))



# Create the database and tables
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Check if there is at least one admin
        admin_user = User.query.filter_by(role='Admin').first()
        if not admin_user:
            # Create a default admin user if none exists
            default_admin = User(username='admin', password=generate_password_hash('admin'), role='Admin', status='approved')
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin created with username 'admin' and password 'admin_password'.")
    app.run(debug=True)
