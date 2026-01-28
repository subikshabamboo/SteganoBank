# 🔐 SteganoBank – Secure Steganography & Audit Blockchain System

A secure web-based steganography system that hides encrypted messages inside images, enhanced with:
- Multi-Factor Authentication (OTP)
- Role-Based Access Control
- Digital Signatures
- Blockchain-based Audit Logs

## 🚀 Features
- LSB Image Steganography
- AES Encryption + SHA-256 Integrity
- RSA Digital Signatures
- Email-based OTP Authentication
- Blockchain Audit Trail (Proof-of-Work)
- QR Code based message sharing
- Role-based access (Admin / Sender / Receiver)

## 🛠 Tech Stack
- Python (Flask)
- SQLite + SQLAlchemy
- Cryptography (AES, RSA, SHA-256)
- SMTP (Email OTP)
- HTML, CSS, Jinja2
- Custom Blockchain Implementation

## 🔑 Security Concepts Implemented
- Confidentiality
- Integrity
- Authentication
- Authorization
- Non-repudiation
- Least Privilege Principle

## 📂 Project Structure
steganography_system/
│
├── app.py
├── config.py.example
├── models.py
├── blockchain.py
├── crypto_utils.py
├── steganography.py
├── encoding.py
├── decorators.py
│
├── templates/
├── static/
├── uploads/
├── stego_images/
│
├── requirements.txt
├── .gitignore
└── README.md