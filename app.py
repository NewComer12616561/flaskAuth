import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

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

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    students = db.relationship('Enrollment', backref='class_enrolled', lazy=True)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # Status: pending, approved, denied    

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
            return redirect(url_for('login'))
    return render_template('register.html')



#defaut route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Check if the user is a teacher and their status
            if user.role == 'Teacher':
                if user.status == 'pending':
                    flash('Your account is pending approval by an admin. Please wait for approval before logging in.')
                    return redirect(url_for('login'))
                elif user.status == 'denied':
                    flash('Your account has been denied. Please contact admin for more information.')
                    return redirect(url_for('login'))
            
            # If the user is approved, log them in
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to the appropriate dashboard
        else:
            flash('Invalid username or password!')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! Your role is {current_user.role}. <a href="/logout">Logout</a>'



@app.route('/logout')
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

#Admin route
# Remove or comment out this route
# @app.route('/admin/approve_teachers')
# @admin_required
# def approve_teachers():
#     pending_teachers = User.query.filter_by(role='Teacher', status='pending').all()
#     return render_template('approve_teachers.html', pending_teachers=pending_teachers)

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



def teacher_required(f):
    @wraps(f)  # Preserve the original function's name and docstring
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['Admin', 'Teacher']:
            flash('Access denied: Admins and Teachers only.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

#view all admin
@app.route('/admin')
@admin_required
def admin_dashboard():
    all_users = User.query.all()
    pending_teachers = User.query.filter_by(role='Teacher', status='pending').all()
    approved_teachers = User.query.filter_by(role='Teacher', status='approved').all()
    students = User.query.filter_by(role='Student').all()
    
    return render_template('admin_dashboard.html', 
                           all_users=all_users, 
                           pending_teachers=pending_teachers, 
                           approved_teachers=approved_teachers, 
                           students=students)

# Teacher route
@app.route('/teacher')
@teacher_required
def teacher_dashboard():
    return 'Welcome to the Teacher Dashboard!'

#view enrollments teacher
@app.route('/teacher/enrollments')
@login_required
@teacher_required
def view_enrollments():
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    return render_template('view_enrollments.html', classes=classes)


@app.route('/teacher/create_class', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_class():
    if request.method == 'POST':
        class_name = request.form['class_name']
        new_class = Class(name=class_name, teacher_id=current_user.id)
        db.session.add(new_class)
        db.session.commit()
        flash('Class created successfully!')
        return redirect(url_for('teacher_dashboard'))  # Redirect to teacher dashboard
    return render_template('create_class.html')

@app.route('/teacher/approve_enrollment/<int:enrollment_id>')
@login_required
@teacher_required
def approve_enrollment(enrollment_id):
    enrollment = Enrollment.query.get(enrollment_id)
    if enrollment:
        enrollment.status = 'approved'
        db.session.commit()
        flash('Enrollment approved.')
    else:
        flash('Enrollment not found.')
    return redirect(url_for('view_enrollments'))

@app.route('/teacher/deny_enrollment/<int:enrollment_id>')
@login_required
@teacher_required
def deny_enrollment(enrollment_id):
    enrollment = Enrollment.query.get(enrollment_id)
    if enrollment:
        enrollment.status = 'denied'
        db.session.commit()
        flash('Enrollment denied.')
    else:
        flash('Enrollment not found.')
    return redirect(url_for('view_enrollments'))

#Student route

#view
@app.route('/classes')
@login_required
def view_classes():
    classes = Class.query.all()  # Get all classes
    return render_template('view_classes.html', classes=classes)

#enroll
@app.route('/enroll/<int:class_id>', methods=['POST'])
@login_required
def enroll(class_id):
    # Check if the user is a student
    if current_user.role != 'Student':
        flash('Only students can enroll in classes.')
        return redirect(url_for('dashboard'))

    # Check if the class exists
    class_to_enroll = Class.query.get(class_id)
    if not class_to_enroll:
        flash('Class not found.')
        return redirect(url_for('dashboard'))

    # Check if the student is already enrolled
    existing_enrollment = Enrollment.query.filter_by(student_id=current_user.id, class_id=class_id).first()
    if existing_enrollment:
        flash('You are already enrolled in this class.')
        return redirect(url_for('dashboard'))

    # Create a new enrollment
    new_enrollment = Enrollment(student_id=current_user.id, class_id=class_id)
    db.session.add(new_enrollment)
    db.session.commit()
    flash('Enrollment request submitted. Waiting for approval.')
    return redirect(url_for('dashboard'))




if __name__ == '__main__':
    # Create the database and tables
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
