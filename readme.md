# 🔐 SteganoSecure - Secure Steganography Messaging System

A comprehensive web-based application that demonstrates multiple security concepts including authentication, authorization, encryption, digital signatures, hashing, and steganography with blockchain-based audit trails.

---

## 📋 Table of Contents

- [Features](#features)
- [Security Components](#security-components)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)

---

## ✨ Features

### Core Functionality

- **🖼️ LSB Steganography**: Hide encrypted messages inside images
- **🔐 AES-256 Encryption**: Military-grade message encryption
- **✍️ RSA Digital Signatures**: Ensure message authenticity
- **🔗 Blockchain Audit Trail**: Immutable logging of all system activities
- **📱 QR Code Generation**: Easy message sharing
- **🔍 Steganalysis Tools**: Chi-square attack detection, histogram analysis

### Security Features

- **🔑 Multi-Factor Authentication (MFA)**: Password + Email OTP
- **👥 Role-Based Access Control (RBAC)**: Admin, Sender, Receiver roles
- **🧂 Salted Password Hashing**: Secure password storage
- **🔒 Message Integrity Verification**: Hash validation
- **🎫 Session Management**: Secure session handling
- **📊 Access Control Matrix**: Fine-grained permissions

---

## 🛡️ Security Components

### 1. Authentication (Multi-Factor)

- **Single-Factor**: Username + Password (hashed with salt)
- **Multi-Factor**: Time-based OTP sent via email (5-minute validity)

### 2. Authorization (Access Control)

Access Control List (ACL) with 3 roles:

- **Admin**: Full system access, blockchain visibility
- **Sender**: Create and manage own messages
- **Receiver**: View received messages only

### 3. Encryption

- **Key Derivation**: Deterministic key generation from sender/receiver IDs
- **AES-256-CBC**: Symmetric encryption with random IV
- **RSA-2048**: Asymmetric key pairs for digital signatures

### 4. Hashing & Digital Signatures

- **SHA-256 Hashing**: With random salt for message integrity
- **RSA-PSS Signatures**: Message authenticity verification

### 5. Encoding Techniques

- **Base64**: Binary data encoding
- **QR Codes**: Message extraction URL encoding
- **LSB Steganography**: Image-based data hiding

### 6. Blockchain Audit

- **Immutable Audit Trail**: All user actions logged
- **Proof-of-Work**: Mining with configurable difficulty
- **Chain Validation**: Integrity verification

---

## 🛠️ Technology Stack

### Backend

- Python 3.8+
- Flask 2.3.0: Web framework
- SQLAlchemy: ORM for database management

### Security Libraries

- **cryptography**: AES encryption, RSA signatures
- **werkzeug.security**: Password hashing
- **pyotp**: OTP generation
- **hashlib**: SHA-256 hashing

### Steganography & Encoding

- **stegano**: LSB steganography
- **PIL (Pillow)**: Image processing
- **qrcode**: QR code generation
- **NumPy & SciPy**: Statistical analysis

### Frontend

- HTML5, CSS3, Bootstrap 5
- Jinja2: Template engine

---

## 📦 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Gmail account (for OTP email delivery)
- Git (for cloning repository)

---

## 🚀 Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/stegano-secure.git
cd stegano-secure
```

### Step 2: Create Virtual Environment

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` prefix in your terminal.

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure the Application

**Create config.py from template**

```bash
# Copy the example config file
cp config.py.example config.py
```

Edit `config.py` with your settings - see Configuration section below

### Step 5: Set Up Gmail App Password

⚠️ **Important: Do NOT use your regular Gmail password!**

1. Go to your Google Account: https://myaccount.google.com/
2. Navigate to Security → 2-Step Verification (enable if not already)
3. Scroll down to App passwords
4. Select app: Mail, Select device: Other (Custom name)
5. Name it: "SteganoSecure App"
6. Copy the 16-character password
7. Paste it in `config.py` as `MAIL_PASSWORD`

**Example:**
```python
MAIL_USERNAME = 'johndoe@gmail.com'
MAIL_PASSWORD = 'abcd efgh ijkl mnop'  # 16-char app password
```

### Step 6: Create Required Folders

```bash
mkdir uploads
mkdir -p static/stego_images
```

### Step 7: Initialize the Database

The database will be automatically created when you first run the app.

---
