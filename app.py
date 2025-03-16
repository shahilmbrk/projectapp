from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask import jsonify
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
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ID of the sender
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ID of the receiver
    content = db.Column(db.Text, nullable=False)  # Message content
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Timestamp of the message

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Coordinator who posted the announcement
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationship with the User model (coordinator who posted the announcement)
    coordinator = db.relationship('User', backref='announcements')
    
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    # Relationship with Document model (documents uploaded by the user)
    documents = db.relationship('Document', backref='uploader', foreign_keys='Document.user_id', lazy=True)

    # Relationship with Document model (documents assigned to the staff)
    staff_documents = db.relationship('Document', backref='staff', foreign_keys='Document.staff_id', lazy=True)
    
    # Student-specific fields
    full_name = db.Column(db.String(100))
    registration_number = db.Column(db.String(50))
    group_number = db.Column(db.String(20))
    group_members = db.Column(db.String(200))  # Store as a JSON string or comma-separated list
    assigned_staff_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Foreign key to assigned staff

    # Relationship with assigned staff
    assigned_staff = db.relationship('User', remote_side=[id], foreign_keys=[assigned_staff_id])

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"
     
    @property
    def password(self):
        raise AttributeError('Password is not readable.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key for the uploader
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key for the assigned staff
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')
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
            elif user.role == 'Staff':
                return redirect(url_for('staff_dashboard'))
            elif user.role == 'Coordinator':
                return redirect(url_for('coordinator_dashboard'))
            elif user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Login Failed. Check username and password.', 'danger')
    return render_template('index.html')


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/staff/dashboard')
@login_required
def staff_dashboard():
    if current_user.role != 'Staff':
        flash('You do not have permission to access the Staff Dashboard.', 'error')
        return redirect(url_for('home'))
    
    # Fetch only the documents assigned to the current staff member
    documents = Document.query.filter_by(staff_id=current_user.id).all()
    return render_template('staff_dashboard.html', documents=documents)

@app.route('/coordinator/dashboard')
@login_required
def coordinator_dashboard():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to access the Coordinator Dashboard.', 'error')
        return redirect(url_for('home'))
    
    # Fetch all documents
    documents = Document.query.all()
    return render_template('coordinator_dashboard.html', documents=documents)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'Student':
        flash('You do not have permission to upload files.', 'error')
        return redirect(url_for('home'))

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('upload_proposal'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('upload_proposal'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Fetch the selected staff member
        staff_name = request.form['staff_name']
        staff_member = User.query.filter_by(username=staff_name, role='Staff').first()

        if not staff_member:
            flash('Selected staff member not found', 'danger')
            return redirect(url_for('upload_proposal'))

        # Save additional details
        new_doc = Document(
            user_id=current_user.id,
            file_name=filename,
            file_path=file_path,
            student_name=request.form['student_name'],
            class_name=request.form['class_name'],
            abstract=request.form['abstract'],
            group_no=request.form['group_no'],
            staff_name=staff_name,
            staff_id=staff_member.id  # Associate document with staff member
        )
        db.session.add(new_doc)
        db.session.commit()
        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type. Allowed types are txt, pdf, docx.', 'danger')

    return redirect(url_for('upload_proposal'))

@app.route('/staff/verify/<int:doc_id>/<action>', methods=['POST'])
@login_required
def verify_document(doc_id, action):
    if current_user.role not in ['Staff', 'Coordinator']:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    doc = Document.query.get_or_404(doc_id)

    if action == 'approve':
        doc.status = 'Approved'
        flash('Document approved successfully!', 'success')
    elif action == 'reject':
        doc.status = 'Rejected'
        flash('Document rejected successfully!', 'success')
    else:
        flash('Invalid action.', 'danger')
        return redirect(url_for('coordinator_dashboard' if current_user.role == 'Coordinator' else 'staff_dashboard'))

    db.session.commit()
    return redirect(url_for('coordinator_dashboard' if current_user.role == 'Coordinator' else 'staff_dashboard'))


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
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all pending registration requests
    registration_requests = RegistrationRequest.query.filter_by(status='Pending').all()
    return render_template('admin_requests.html', registration_requests=registration_requests)

@app.route('/admin/students')
@login_required
def admin_students():
    if current_user.role != 'Admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all students
    students = User.query.filter_by(role='Student').all()
    return render_template('admin_students.html', students=students)

@app.route('/admin/staff')
@login_required
def admin_staff():
    if current_user.role != 'Admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all staff members
    staff_members = User.query.filter_by(role='Staff').all()
    return render_template('admin_staff.html', staff_members=staff_members)

@app.route('/admin/coordinators')
@login_required
def admin_coordinators():
    if current_user.role != 'Admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all coordinators
    coordinators = User.query.filter_by(role='Coordinator').all()
    return render_template('admin_coordinators.html', coordinators=coordinators)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/approve/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    if current_user.role != 'Admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    # Fetch the registration request
    request = RegistrationRequest.query.get_or_404(request_id)

    # Create a new user
    new_user = User(
        username=request.username,
        role=request.role,
        password_hash=request.password_hash  # Use the hashed password from the request
    )
    db.session.add(new_user)

    # Update the request status
    request.status = 'Approved'
    db.session.commit()

    flash(f'Registration request for {request.username} approved.', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/admin/reject/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    if current_user.role != 'Admin':
        flash('You do not have permission to perform this action.', 'error')
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

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch all staff members
    staff_members = User.query.filter_by(role='Staff').all()
    return render_template('student_dashboard.html', staff_members=staff_members)

@app.route('/account')
@login_required
def account():
    if current_user.role != 'Student':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all staff members for the dropdown
    staff_members = User.query.filter_by(role='Staff').all()
    return render_template('account.html', staff_members=staff_members)

@app.route('/update_account', methods=['POST'])
@login_required
def update_account():
    if current_user.role != 'Student':
        flash('You do not have permission to update details.', 'error')
        return redirect(url_for('home'))

    # Update student details
    current_user.full_name = request.form.get('full_name')
    current_user.registration_number = request.form.get('registration_number')
    current_user.group_number = request.form.get('group_number')
    current_user.group_members = request.form.get('group_members')
    current_user.assigned_staff_id = request.form.get('assigned_staff')

    db.session.commit()
    flash('Your details have been updated successfully!', 'success')
    return redirect(url_for('account'))

@app.route('/project')
@login_required
def project():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    # Fetch the current student's uploaded files
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('project.html', documents=documents)



@app.route('/help_support')
@login_required
def help_support():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    return render_template('help_support.html')

# Helper function
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload_proposal')
@login_required
def upload_proposal():
    if current_user.role != 'Student':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all staff members for the dropdown
    staff_members = User.query.filter_by(role='Staff').all()
    return render_template('upload_proposal.html', staff_members=staff_members)

@app.route('/student_details')
@login_required
def student_details():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all students
    students = User.query.filter_by(role='Student').all()
    return render_template('student_details.html', students=students)

@app.route('/project_proposals')
@login_required
def project_proposals():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all documents
    documents = Document.query.all()
    return render_template('project_proposals.html', documents=documents)

@app.route('/manage_groups')
@login_required
def manage_groups():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch all students and staff members
    students = User.query.filter_by(role='Student').all()
    staff_members = User.query.filter_by(role='Staff').all()
    return render_template('manage_groups.html', students=students, staff_members=staff_members)

@app.route('/assign_staff', methods=['POST'])
@login_required
def assign_staff():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    student_id = request.form.get('student')
    staff_id = request.form.get('staff')

    student = User.query.get_or_404(student_id)
    staff = User.query.get_or_404(staff_id)

    student.assigned_staff_id = staff.id
    db.session.commit()

    flash(f'{student.username} has been assigned to {staff.username}.', 'success')
    return redirect(url_for('manage_groups'))

@app.route('/announcement')
@login_required
def announcement():
    # Fetch all announcements
    announcements = Announcement.query.order_by(Announcement.post_date.desc()).all()
    return render_template('announcement.html', announcements=announcements)

@app.route('/post_announcement', methods=['POST'])
@login_required
def post_announcement():
    if current_user.role != 'Coordinator':
        flash('You do not have permission to post announcements.', 'error')
        return redirect(url_for('announcement'))

    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        flash('Title and content are required.', 'danger')
        return redirect(url_for('announcement'))

    # Create a new announcement
    new_announcement = Announcement(
        title=title,
        content=content,
        posted_by=current_user.id
    )
    db.session.add(new_announcement)
    db.session.commit()

    flash('Announcement posted successfully!', 'success')
    return redirect(url_for('announcement'))

@app.route('/staff/communication')
@login_required
def staff_communication():
    if current_user.role != 'Staff':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch students assigned to the staff
    assigned_students = User.query.filter_by(assigned_staff_id=current_user.id, role='Student').all()
    return render_template('staff_communication.html', assigned_students=assigned_students)

@app.route('/student/communication')
@login_required
def student_communication():
    if current_user.role != 'Student':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Ensure the student has an assigned staff
    if not current_user.assigned_staff_id:
        flash('No staff assigned to you.', 'error')
        return redirect(url_for('student_dashboard'))

    return render_template('student_communication.html')

@app.route('/staff/project_proposals')
@login_required
def staff_project_proposals():
    if current_user.role != 'Staff':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch documents assigned to the staff
    documents = Document.query.filter_by(staff_id=current_user.id).all()
    return render_template('staff_project_proposals.html', documents=documents)

@app.route('/staff/manage')
@login_required
def staff_manage():
    if current_user.role != 'Staff':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch students assigned to the staff
    assigned_students = User.query.filter_by(assigned_staff_id=current_user.id, role='Student').all()
    return render_template('staff_manage.html', assigned_students=assigned_students)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.json.get('receiver_id')
    content = request.json.get('message')

    if not receiver_id or not content:
        return jsonify({'error': 'Invalid request'}), 400

    # Create a new message
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/get_messages/<int:user_id>')
@login_required
def get_messages(user_id):
    # Fetch messages between the current user and the selected user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()

    # Format messages for JSON response
    messages_data = [{
        'sender_id': msg.sender_id,
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat()  # Convert datetime to string
    } for msg in messages]

    return jsonify(messages_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)