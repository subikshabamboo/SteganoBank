# models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import pytz

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='sender')  # admin, sender, receiver
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    
    # RSA keys for digital signatures
    private_key_pem = db.Column(db.Text)
    public_key_pem = db.Column(db.Text)
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    
    def set_password(self, password):
        """Hash password with salt using Werkzeug"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_signing_keys(self):
        """Generate RSA-2048 keypair for digital signatures"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.private_key_pem = private_pem.decode('utf-8')
        self.public_key_pem = public_pem.decode('utf-8')
    
    def __repr__(self):
        return f'<User {self.username}>'


class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    original_filename = db.Column(db.String(200))
    stego_image_path = db.Column(db.String(200), nullable=False)
    
    encrypted_message = db.Column(db.Text, nullable=False)
    iv = db.Column(db.String(200), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    message_hash = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    is_read = db.Column(db.Boolean, default=False)
    
    def can_view(self, user):
        """Check if user can view this message"""
        return (user.id == self.sender_id or 
                user.id == self.receiver_id or 
                user.role == 'admin')
    
    def can_delete(self, user):
        """Check if user can delete this message"""
        return user.id == self.sender_id or user.role == 'admin'
    
    def __repr__(self):
        return f'<Message {self.id} from User {self.sender_id}>'