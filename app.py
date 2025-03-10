from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'docx'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Ensure this is NOT NULL
    role = db.Column(db.String(20), nullable=False)
    documents = db.relationship('Document', backref='user', lazy=True)

    @property
    def password(self):
        raise AttributeError('Password is not readable.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)  # Hash the password

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)     

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')
    # New fields
    student_name = db.Column(db.String(50), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    abstract = db.Column(db.Text, nullable=False)
    group_no = db.Column(db.String(20), nullable=False)
    staff_name = db.Column(db.String(50), nullable=False)

class RegistrationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Ensure this is NOT NULL
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected

    @property
    def password(self):
        raise AttributeError('Password is not readable.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)  # Hash the password

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Verify the password using the verify_password method
        if user and user.verify_password(password):
            login_user(user)
            if user.role == 'Student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'Staff' or user.role == 'Coordinator':
                return redirect(url_for('staff_dashboard'))
            elif user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Login Failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch the current student's uploaded files
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('student_dashboard.html', documents=documents)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/staff/dashboard')
@login_required
def staff_dashboard():
    if current_user.role not in ['Staff', 'Coordinator']:
        return redirect(url_for('home'))
    documents = Document.query.all()  # Fetch all documents from the database
    return render_template('staff_dashboard.html', documents=documents)

@app.route('/coordinator/dashboard')
@login_required
def coordinator_dashboard():
    if current_user.role != 'Coordinator':
        return redirect(url_for('home'))
    documents = Document.query.all()  # Fetch all documents from the database
    return render_template('coordinator_dashboard.html', documents=documents)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/student/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('student_dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Ensure the filename is safe
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Save additional details
        new_doc = Document(
            user_id=current_user.id,
            file_name=filename,
            file_path=file_path,
            student_name=request.form['student_name'],
            class_name=request.form['class_name'],
            abstract=request.form['abstract'],
            group_no=request.form['group_no'],
            staff_name=request.form['staff_name']
        )
        db.session.add(new_doc)
        db.session.commit()
        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type. Allowed types are txt, pdf, docx.', 'danger')
    
    return redirect(url_for('student_dashboard'))

@app.route('/staff/verify/<int:doc_id>', methods=['POST'])
@login_required
def verify_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    doc.status = 'Verified'
    db.session.commit()
    flash('Document verified', 'success')
    return redirect(url_for('staff_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if username already exists in User or RegistrationRequest
        if User.query.filter_by(username=username).first() or RegistrationRequest.query.filter_by(username=username).first():
            flash('Username already exists. Choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        # Create a new registration request
        new_request = RegistrationRequest(
            username=username,
            role=role,
            status='Pending'
        )
        new_request.password = password  # Set the password (hashes it automatically)
        db.session.add(new_request)
        db.session.commit()
        flash('Registration request submitted. Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin/requests')
@login_required
def admin_requests():
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    
    # Fetch all pending registration requests
    requests = RegistrationRequest.query.filter_by(status='Pending').all()
    return render_template('admin_requests.html', requests=requests)

@app.route('/admin/approve/<int:request_id>')
@login_required
def approve_request(request_id):
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    
    # Fetch the registration request
    request = RegistrationRequest.query.get_or_404(request_id)
    
    # Create a new user
    new_user = User(
        username=request.username,
        role=request.role
    )
    new_user.password_hash = request.password_hash  # Use the hashed password from the request
    db.session.add(new_user)
    
    # Update the request status
    request.status = 'Approved'
    db.session.commit()
    
    flash(f'Registration request for {request.username} approved.', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/admin/reject/<int:request_id>')
@login_required
def reject_request(request_id):
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    
    # Fetch the registration request
    request = RegistrationRequest.query.get_or_404(request_id)
    
    # Update the request status
    request.status = 'Rejected'
    db.session.commit()
    
    flash(f'Registration request for {request.username} rejected.', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Helper function
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)