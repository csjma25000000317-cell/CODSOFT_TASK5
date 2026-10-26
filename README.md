# VaultShare – Secure File Sharing System

## About the Project
VaultShare is a secure file-sharing web application developed using Python and Flask. It allows users to register, log in, upload files, manage their private files, and create time-limited sharing links.

The project focuses on privacy, controlled file access, and secure file management.

## Features
- **User Authentication:** User registration, login, and logout.
- **Secure File Storage:** File encryption using the Fernet cryptography system.
- **File Management:** Upload, view, download, and delete files.
- **Time-Limited Sharing:** Generate links that expire after a specified duration.
- **Access Control:** Protect private files from unauthorized access.
- **Admin Panel:** Manage users and their roles.
- **Responsive Interface:** Modern interface designed for desktop and mobile screens.
- **File Validation:** File extension restrictions and upload size limits.

## Technologies Used
- Python
- Flask
- HTML5
- CSS3
- JavaScript
- SQLite
- Cryptography (Fernet)

## Project Structure

```text
VaultShare/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   ├── base.html
│   ├── landing.html
│   ├── auth.html
│   ├── dashboard.html
│   ├── share_created.html
│   ├── public_share.html
│   ├── share_expired.html
│   ├── admin.html
│   └── error.html
├── static/
│   ├── style.css
│   └── script.js
└── private_storage/
    └── .gitkeep
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd VaultShare
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the actual repository URL.

### 2. Create a Virtual Environment (Optional)

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

Open the local address displayed in the terminal, usually:

```text
http://127.0.0.1:5000
```

## Security Notes
- Do not upload encryption keys, application secrets, databases containing private user information, or uploaded private files to a public repository.
- Keep secret files excluded through `.gitignore`.
- Use HTTPS, CSRF protection, secure production configuration, and persistent protected storage before deploying publicly.
- Preserve the encryption key securely; encrypted files may become unrecoverable if the key is lost.

## Learning Outcomes
This project demonstrates practical implementation of web application development, user authentication, file encryption, access control, and controlled file sharing using Python and Flask.

## Project Status
The application has been developed and tested locally. Public deployment and production security configuration should be verified separately.

## Author
Developed as part of the CODSOFT Cyber Security Internship – Task 5.
