# RiskRAG - RISK Knowledge Base AI

A comprehensive knowledge management and AI-powered question-answering system for RISK company.

## Features

### 🤖 AI-Powered Q&A
- Ask questions about uploaded documents and get intelligent answers
- Automatic citation generation with source references
- Support for both shared and private document search
- Smart citation filtering - only shows sources actually used in answers

### 📚 Document Management
- Upload and manage PDF, DOCX, and text documents
- Support for both private and shared documents
- Improved PDF text extraction with formatting preservation
- View original PDF format or extracted text
- Document categorization and organization

### 💬 Chat Management System
- **Multiple Chats**: Create and manage multiple conversation threads
- **Automatic Title Generation**: Chat titles are automatically generated based on conversation content
- **Chat History**: All conversations are persistently saved
- **Smart Summarization**: Titles are short and descriptive (max 40 characters)
- **Topic Detection**: Automatically identifies business topics like Risk, Compliance, Security, etc.

### 👥 User Management
- User registration and authentication
- Role-based access control (Admin/User)
- Private document isolation
- Admin panel for user management

### 📊 Admin Features
- User management and statistics
- Document reprocessing capabilities
- System overview and monitoring

## Chat Title Generation

The system automatically generates descriptive chat titles based on conversation content:

### Examples:
- **"What is our risk management policy?"** → **"Risk Management Policy"**
- **"How do we handle cybersecurity compliance?"** → **"Security & Compliance"**
- **"Tell me about financial reporting procedures"** → **"Finance Discussion"**
- **"What are the audit requirements?"** → **"Audit Discussion"**

### Title Generation Strategies:
1. **Topic Detection**: Identifies business topics (Risk, Compliance, Security, Finance, etc.)
2. **Smart Truncation**: Intelligently shortens long questions
3. **Prefix Removal**: Removes common question prefixes ("What is", "How to", etc.)
4. **Document Type Recognition**: Identifies document types (Policy, Report, Contract, etc.)

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up environment variables in `.env`:
   ```
   SECRET_KEY=your_secret_key
   DEEPSEEK_API_KEY=your_deepseek_api_key
   ```
4. Run the application: `python app.py`
5. Access at `http://localhost:5001`

## Usage

### Getting Started
1. Register an account or login as admin (admin/admin)
2. Upload documents to your private or shared space
3. Start asking questions in the "Ask Me" tab
4. Create new chats for different topics
5. View citations and source documents

### Chat Management
- **New Chat**: Click "New Chat" button or ask a question to auto-create
- **Switch Chats**: Click any chat in the sidebar to switch
- **Edit Titles**: Hover over chat and click edit icon
- **Delete Chats**: Hover over chat and click delete icon
- **Automatic Titles**: Chat titles update automatically based on conversation

### Document Viewing
- **Original PDF**: View documents in their original format
- **Extracted Text**: View processed text with highlighting
- **Citations**: Click citation links to view source sections
- **Dual View**: Toggle between PDF and text views

## Technical Details

### Backend
- **Flask**: Web framework
- **SQLAlchemy**: Database ORM
- **FAISS**: Vector similarity search
- **Sentence Transformers**: Text embeddings
- **DeepSeek API**: LLM for answer generation

### Frontend
- **HTML/CSS/JavaScript**: Modern responsive interface
- **Material Icons**: Clean iconography
- **Real-time Updates**: Live chat title updates

### Database Models
- **User**: User accounts and authentication
- **Document**: Document storage and metadata
- **Note**: User-created notes
- **Chat**: Chat sessions and metadata
- **ChatMessage**: Individual messages with citations

## API Endpoints

### Chat Management
- `POST /chat` - Create new chat
- `GET /chat/<id>` - Load chat messages
- `DELETE /chat/<id>` - Delete chat
- `PUT /chat/<id>/title` - Update chat title

### Q&A
- `POST /ask_question` - Ask question with chat support
- `GET /get_citation_document/<id>` - Get citation document info
- `GET /get_pdf_data/<id>` - Get PDF data for inline viewing

### Document Management
- `POST /upload_document` - Upload new document
- `GET /download_document/<id>` - Download document
- `DELETE /delete_document/<id>` - Delete document

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.
