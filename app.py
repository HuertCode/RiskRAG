import os
import json
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError
from dotenv import load_dotenv
import PyPDF2
import docx
import markdown
import bleach
from rag_system import RAGSystem

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_kb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'private'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'shared'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize RAG system
rag_system = RAGSystem()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text)
    is_shared = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('documents', lazy=True))

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_shared = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('notes', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Username already exists. Choose a different one.')
    
    def validate_email(self, email):
        existing_user = User.query.filter_by(email=email.data).first()
        if existing_user:
            raise ValidationError('Email already registered. Choose a different one.')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=120)])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=4, max=80)])
    submit = SubmitField('Reset Password')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=1, max=255)])
    content = TextAreaField('Content', validators=[InputRequired()])
    submit = SubmitField('Save Note')

# Helper functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'md'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path, filename):
    """Extract text content from uploaded files"""
    text = ""
    file_ext = filename.rsplit('.', 1)[1].lower()
    
    try:
        if file_ext == 'txt' or file_ext == 'md':
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
                if file_ext == 'md':
                    text = markdown.markdown(text)
                    text = bleach.clean(text, strip=True)
        elif file_ext == 'pdf':
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
        elif file_ext in ['doc', 'docx']:
            doc = docx.Document(file_path)
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
    except Exception as e:
        print(f"Error extracting text from {filename}: {str(e)}")
        text = f"Error reading file: {str(e)}"
    
    return text

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('private_documents'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('private_documents'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password reset successful')
            return redirect(url_for('login'))
        flash('Email not found')
    return render_template('reset_password.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/private_documents')
@login_required
def private_documents():
    documents = Document.query.filter_by(user_id=current_user.id, is_shared=False).all()
    notes = Note.query.filter_by(user_id=current_user.id, is_shared=False).all()
    return render_template('private_documents.html', documents=documents, notes=notes)

@app.route('/shared_documents')
@login_required
def shared_documents():
    documents = Document.query.filter_by(is_shared=True).all()
    notes = Note.query.filter_by(is_shared=True).all()
    return render_template('shared_documents.html', documents=documents, notes=notes)

@app.route('/ask_me')
@login_required
def ask_me():
    return render_template('ask_me.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('private_documents'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/upload_document', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    is_shared = request.form.get('is_shared') == 'true'
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        folder = 'shared' if is_shared else 'private'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, unique_filename)
        file.save(file_path)
        
        # Extract text content
        content = extract_text_from_file(file_path, filename)
        
        # Save to database
        document = Document(
            filename=unique_filename,
            original_filename=filename,
            file_path=file_path,
            content=content,
            is_shared=is_shared,
            user_id=current_user.id
        )
        db.session.add(document)
        db.session.commit()
        
        # Add to RAG system
        rag_system.add_document(document.id, content, {
            'filename': filename,
            'user_id': current_user.id,
            'is_shared': is_shared,
            'created_at': document.created_at.isoformat()
        })
        
        return jsonify({'message': 'File uploaded successfully'})
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/save_note', methods=['POST'])
@login_required
def save_note():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    is_shared = data.get('is_shared', False)
    note_id = data.get('note_id')
    
    if not title or not content:
        return jsonify({'error': 'Title and content are required'}), 400
    
    if note_id:
        # Update existing note
        note = Note.query.get_or_404(note_id)
        if note.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        note.title = title
        note.content = content
        note.is_shared = is_shared
        note.updated_at = datetime.utcnow()
    else:
        # Create new note
        note = Note(
            title=title,
            content=content,
            is_shared=is_shared,
            user_id=current_user.id
        )
        db.session.add(note)
    
    db.session.commit()
    
    # Add/update in RAG system
    rag_system.add_document(f"note_{note.id}", content, {
        'title': title,
        'type': 'note',
        'user_id': current_user.id,
        'is_shared': is_shared,
        'created_at': note.created_at.isoformat()
    })
    
    return jsonify({'message': 'Note saved successfully', 'note_id': note.id})

@app.route('/delete_document/<int:doc_id>', methods=['DELETE'])
@login_required
def delete_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete file
    if os.path.exists(document.file_path):
        os.remove(document.file_path)
    
    # Remove from RAG system
    rag_system.remove_document(doc_id)
    
    db.session.delete(document)
    db.session.commit()
    
    return jsonify({'message': 'Document deleted successfully'})

@app.route('/delete_note/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Remove from RAG system
    rag_system.remove_document(f"note_{note_id}")
    
    db.session.delete(note)
    db.session.commit()
    
    return jsonify({'message': 'Note deleted successfully'})

@app.route('/view_document/<int:doc_id>')
@login_required
def view_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Check permissions
    if not document.is_shared and document.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('private_documents'))
    
    return render_template('view_document.html', document=document)

@app.route('/download_document/<int:doc_id>')
@login_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Check permissions
    if not document.is_shared and document.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('private_documents'))
    
    return send_file(document.file_path, as_attachment=True, download_name=document.original_filename)

@app.route('/ask_question', methods=['POST'])
@login_required
def ask_question():
    data = request.get_json()
    question = data.get('question')
    private_mode = data.get('private_mode', False)
    
    if not question:
        return jsonify({'error': 'Question is required'}), 400
    
    # Get relevant documents based on mode
    if private_mode:
        # Only user's private documents
        user_docs = Document.query.filter_by(user_id=current_user.id, is_shared=False).all()
        user_notes = Note.query.filter_by(user_id=current_user.id, is_shared=False).all()
        doc_ids = [doc.id for doc in user_docs] + [f"note_{note.id}" for note in user_notes]
    else:
        # All shared documents
        shared_docs = Document.query.filter_by(is_shared=True).all()
        shared_notes = Note.query.filter_by(is_shared=True).all()
        doc_ids = [doc.id for doc in shared_docs] + [f"note_{note.id}" for note in shared_notes]
    
    # Get answer from RAG system
    answer, citations = rag_system.get_answer(question, doc_ids)
    
    return jsonify({
        'answer': answer,
        'citations': citations
    })

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        return jsonify({'error': 'Cannot delete admin user'}), 400
    
    # Delete user's documents and notes
    for doc in user.documents:
        if os.path.exists(doc.file_path):
            os.remove(doc.file_path)
        rag_system.remove_document(doc.id)
    
    for note in user.notes:
        rag_system.remove_document(f"note_{note.id}")
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    return jsonify({'message': f'User admin status updated', 'is_admin': user.is_admin})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@risk.com', is_admin=True)
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)