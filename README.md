# RISK Knowledge Base

A Flask-based web application that serves as a knowledge base using RAG (Retrieval-Augmented Generation) technology, powered by the Deepseek API.

## Features

- **User Authentication**: Registration, login, and password reset functionality
- **Admin Panel**: User management for administrators  
- **Private Documents**: Upload and manage personal documents (PDFs, Word docs, text files)
- **Shared Documents**: Upload documents to share with the entire organization
- **AI-Powered Q&A**: Ask questions and get answers with citations from documents
- **Private Mode**: Toggle between private documents and shared documents for answers
- **Google-Style UI**: Modern, responsive design inspired by Google's Material Design

## Setup Instructions

### 1. Prerequisites
- Python 3.8 or higher
- Virtual environment (recommended)

### 2. Installation

1. Clone or download the project files
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   - Copy the `.env` file and update the values:
   ```bash
   SECRET_KEY=your-secret-key-here-change-this-in-production
   DEEPSEEK_API_KEY=your-deepseek-api-key-here
   FLASK_ENV=development
   FLASK_DEBUG=True
   ```

### 3. Running the Application

1. Activate your virtual environment:
   ```bash
   source venv/bin/activate
   ```

2. Start the Flask application:
   ```bash
   python app.py
   ```

3. Open your browser and navigate to `http://localhost:5000`

## Usage

### Login
- **Admin Credentials**: Username: `admin`, Password: `admin`
- Create new user accounts via the registration page

### Tabs Overview

#### 1. Private Documents
- Upload personal documents (PDF, DOCX, TXT, MD)
- Create and edit text notes
- Documents are only visible to you
- Drag-and-drop file upload support

#### 2. Shared Documents  
- Upload documents to share with the organization
- Create shared text notes
- View documents shared by other users
- Only edit/delete your own shared documents

#### 3. Ask Me (AI Q&A)
- Ask questions about your documents
- **Private Mode OFF**: Answers from all shared documents (default)
- **Private Mode ON**: Answers only from your private documents
- Click citations to view source document paragraphs
- Real-time chat interface

### Admin Features
- Access via the Admin tab (admin users only)
- View user statistics
- Manage user accounts (toggle admin status, delete users)
- Cannot delete the main admin account

## API Configuration

To use the AI features, you need a Deepseek API key:

1. Sign up at [Deepseek](https://deepseek.com)
2. Get your API key
3. Update the `DEEPSEEK_API_KEY` in your `.env` file

## File Structure

```
├── app.py                 # Main Flask application
├── rag_system.py         # RAG system implementation
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── reset_password.html
│   ├── private_documents.html
│   ├── shared_documents.html
│   ├── ask_me.html
│   ├── admin.html
│   └── view_document.html
├── uploads/              # File upload directories
│   ├── private/          # Private documents
│   └── shared/           # Shared documents
└── instance/             # Database and instance files
    └── risk_kb.db        # SQLite database
```

## Technical Details

- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite (development) / PostgreSQL (production ready)
- **Authentication**: Flask-Login with session management
- **AI/ML**: Sentence Transformers for embeddings, FAISS for vector search
- **File Processing**: PyPDF2 (PDF), python-docx (Word), Markdown support
- **Security**: CSRF protection, password hashing, input sanitization

## Troubleshooting

### Common Issues

1. **Permission errors during installation**:
   ```bash
   # Use virtual environment
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Missing system packages (Ubuntu/Debian)**:
   ```bash
   sudo apt update
   sudo apt install python3-venv python3-pip
   ```

3. **Database issues**:
   - Delete `instance/risk_kb.db` and restart the app to recreate the database

4. **File upload issues**:
   - Ensure `uploads/private/` and `uploads/shared/` directories exist
   - Check file size limits (default: 16MB)

## Development

The application is ready for development and testing. For production deployment:

1. Change `SECRET_KEY` to a secure random value
2. Set `FLASK_ENV=production` and `FLASK_DEBUG=False`
3. Configure a production database (PostgreSQL recommended)
4. Set up proper web server (Gunicorn + Nginx)
5. Configure SSL/HTTPS

## Support

For questions or issues, please check the troubleshooting section or create an issue in the project repository.
