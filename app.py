# app.py
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import os
import hashlib
import pyotp
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from blockchain import audit_chain
from sqlalchemy import text


from config import Config
from models import db, User, Message
from crypto_utils import MessageEncryption, HashingUtils, DigitalSignature, KeyDerivation
from steganography import Steganography
from encoding import QREncoder
from decorators import login_required, role_required

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Create upload folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['STEGO_FOLDER'], exist_ok=True)

# Helper function for allowed files
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function to send OTP email
# def send_otp_email(email, otp):
#     """Send OTP via email (simplified for demo)"""
#     try:
#         # For demo purposes, just print to console
#         # In production, configure SMTP properly
#         print(f"\n{'='*50}")
#         print(f"OTP for {email}: {otp}")
#         print(f"{'='*50}\n")
        
        
#         msg = MIMEText(f"Your OTP: {otp}\n\nValid for 5 minutes.")
#         msg['Subject'] = 'Steganography System - Login OTP'
#         msg['From'] = app.config['MAIL_USERNAME']
#         msg['To'] = email
        
#         with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
#             server.starttls()
#             server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
#             server.send_message(msg)
        
#         return True
#     except Exception as e:
#         print(f"Email error: {e}")
#         return False
def send_otp_email(email, otp):
    """Send OTP via email"""
    try:
        print(f"\n{'='*50}")
        #print(f"📧 Attempting to send OTP to: {email}")
        print(f"📧 From email: {app.config['MAIL_USERNAME']}")
        print(f"📧 OTP: {otp}")
        #print(f"📧 SMTP Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"{'='*50}\n")
        
        msg = MIMEText(f"Your OTP: {otp}\n\nValid for 5 minutes.")
        msg['Subject'] = 'Steganography System - Login OTP'
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = email
        
        #print("🔌 Connecting to Gmail SMTP server...")
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.set_debuglevel(1)  # Show detailed SMTP conversation
            
            #print("🔒 Starting TLS encryption...")
            server.starttls()
            
            #print("🔑 Logging in...")
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            
            #print("📨 Sending email...")
            server.send_message(msg)
            
        print(f"✅ Email sent successfully to {email}\n")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"\n❌ AUTHENTICATION FAILED: {e}")
        print("Check your App Password in config.py")
        return False
    except Exception as e:
        print(f"\n❌ EMAIL ERROR: {e}")
        print(f"Error type: {type(e).__name__}\n")
        return False
# ============================================
# ROUTES
# ============================================

@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/access-rights')
@login_required
def access_rights():
    return render_template('access_rights.html')


# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'sender')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        new_user.generate_signing_keys()  # Generate RSA keys
        
        db.session.add(new_user)
        db.session.commit()

        # Add to blockchain audit trail
        audit_chain.add_transaction(
        transaction_type='USER_REGISTERED',
        user=new_user.username,
        details=f"New user registered with role: {role}"
        )
        audit_chain.mine_pending_transactions()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Single-factor login (username + password)"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Store user info for MFA step
            session['pending_user_id'] = user.id
            session['mfa_verified'] = False
            
            flash('Password verified. Please enter OTP sent to your email.', 'info')
            return redirect(url_for('verify_mfa'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    """Multi-factor authentication with OTP"""
    if 'pending_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['pending_user_id'])
    
    if request.method == 'GET':
        # Generate OTP
        totp = pyotp.TOTP(pyotp.random_base32(), interval=300)  # 5 min validity
        otp = totp.now()
        
        # Store in session
        session['otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).timestamp()
        
        # Send OTP
        send_otp_email(user.email, otp)
        
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        
        if 'otp' not in session:
            flash('OTP expired. Please request new OTP.', 'error')
            return redirect(url_for('verify_mfa'))
        
        # Check expiry
        if datetime.now().timestamp() > session.get('otp_expiry', 0):
            flash('OTP expired. Please request new OTP.', 'error')
            session.pop('otp', None)
            return redirect(url_for('verify_mfa'))
        
        # Verify OTP
        if entered_otp == session.get('otp'):
            # MFA Success - Complete login
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['mfa_verified'] = True
            
            # Clear temporary data
            session.pop('pending_user_id', None)
            session.pop('otp', None)
            session.pop('otp_expiry', None)

            # Add to blockchain audit trail
            audit_chain.add_transaction(
            transaction_type='USER_LOGIN',
            user=user.username,
            details=f"Successful login with MFA from role: {user.role}"
            )
            audit_chain.mine_pending_transactions()
            
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('verify_mfa.html', email=user.email)

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

# ============================================
# MAIN APPLICATION ROUTES
# ============================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = User.query.get(session['user_id'])
    
    # Get messages based on role
    if user.role == 'sender':
        messages = Message.query.filter_by(sender_id=user.id).order_by(Message.created_at.desc()).all()
    elif user.role == 'receiver':
        messages = Message.query.filter_by(receiver_id=user.id).order_by(Message.created_at.desc()).all()
    else:  # admin
        messages = Message.query.order_by(Message.created_at.desc()).all()
    
    return render_template('dashboard.html', user=user, messages=messages)

@app.route('/hide-message', methods=['GET', 'POST'])
@login_required
@role_required('sender', 'admin')
def hide_message():
    """Hide message in image"""
    if request.method == 'POST':
        try:
            # Get form data
            message_text = request.form.get('message')
            receiver_id = request.form.get('receiver_id')
            image_file = request.files.get('image')
            
            # Validation
            if not message_text or not receiver_id or not image_file:
                flash('All fields are required', 'error')
                return redirect(url_for('hide_message'))
            
            if not allowed_file(image_file.filename):
                flash('Only PNG, JPG, JPEG files allowed', 'error')
                return redirect(url_for('hide_message'))
            
            # Get users
            sender = User.query.get(session['user_id'])
            receiver = User.query.get(receiver_id)
            
            if not receiver:
                flash('Invalid receiver', 'error')
                return redirect(url_for('hide_message'))
            
            # Save uploaded image
            filename = secure_filename(image_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            cover_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamp}_{filename}")
            image_file.save(cover_image_path)
            
            # STEP 1: Hash message for integrity
            hash_result = HashingUtils.hash_message(message_text)
            message_hash = hash_result['hash']
            salt = hash_result['salt']
            
            # STEP 2: Sign message for authenticity
            signature = DigitalSignature.sign_message(message_text, sender.private_key_pem)
            
            # STEP 3: Derive encryption key
            aes_key = KeyDerivation.derive_key(sender.id, receiver.id)
            
            # STEP 4: Encrypt message
            encrypted_data = MessageEncryption.encrypt(message_text, aes_key)
            
            # STEP 5: Create payload (encrypted message + metadata)
            payload = f"{encrypted_data['ciphertext']}|||{encrypted_data['iv']}|||{signature}|||{message_hash}|||{salt}"
            
            # STEP 6: Hide payload in image using steganography
            stego_filename = f"stego_{timestamp}_{filename.rsplit('.', 1)[0]}.png"
            stego_image_path = os.path.join(app.config['STEGO_FOLDER'], stego_filename)
            
            success = Steganography.hide_message(cover_image_path, payload, stego_image_path)
            
            if not success:
                flash('Failed to hide message in image. Try a larger image.', 'error')
                os.remove(cover_image_path)
                return redirect(url_for('hide_message'))
            
            # STEP 7: Save to database
            new_message = Message(
                sender_id=sender.id,
                receiver_id=receiver.id,
                original_filename=filename,
                stego_image_path=stego_image_path,
                encrypted_message=encrypted_data['ciphertext'],
                iv=encrypted_data['iv'],
                signature=signature,
                message_hash=message_hash,
                salt=salt
            )
            db.session.add(new_message)
            db.session.commit()

            # 🔗 Blockchain audit log: message hidden
            audit_chain.add_transaction(
            transaction_type='MESSAGE_HIDDEN',
            user=sender.username,
            details=f"Hidden message for {receiver.username} in {filename}"
            )
            audit_chain.mine_pending_transactions()

            # Clean up original image
            os.remove(cover_image_path)
            
            flash('Message hidden successfully! Share the image or QR code.', 'success')
            return redirect(url_for('message_success', message_id=new_message.id))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('hide_message'))
    
    # GET - show form
    receivers = User.query.filter_by(role='receiver').all()
    return render_template('hide_message.html', receivers=receivers)

@app.route('/message-success/<int:message_id>')
@login_required
def message_success(message_id):
    """Show success page with QR code"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    if not message.can_view(user):
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate QR code
    qr_data = QREncoder.generate_message_qr(message.id, request.url_root)
    
    return render_template('message_success.html', message=message, qr_code=qr_data)

@app.route('/compare/<int:message_id>')
@login_required
def compare_images(message_id):
    """Compare original and stego images side by side"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    if not message.can_view(user):
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('compare_images.html', message=message)

@app.route('/analyze/<int:message_id>')
@login_required
def analyze_stego(message_id):
    """Run steganalysis on the stego image"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    if not message.can_view(user):
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    
    
    # Run analysis
    chi_square = Steganography.chi_square_attack(message.stego_image_path)
    histogram = Steganography.histogram_analysis(message.stego_image_path)
    quality = Steganography.visual_quality_metrics(message.stego_image_path)
    
    return render_template('steganalysis.html',
                         message=message,
                         chi_square=chi_square,
                         histogram=histogram,
                         quality=quality)

@app.route('/extract/<int:message_id>')
@login_required
def extract_message(message_id):
    """Extract and decrypt message"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    # Access control check
    if not message.can_view(user):
        flash('Unauthorized: You cannot access this message', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # STEP 1: Extract payload from image
        payload = Steganography.extract_message(message.stego_image_path)
        
        if not payload:
            flash('No hidden message found in image', 'error')
            return redirect(url_for('dashboard'))
        
        # STEP 2: Parse payload
        parts = payload.split('|||')
        if len(parts) != 5:
            flash('Invalid message format', 'error')
            return redirect(url_for('dashboard'))
        
        ciphertext, iv, signature, msg_hash, salt = parts
        
        # STEP 3: Derive decryption key
        aes_key = KeyDerivation.derive_key(message.sender_id, message.receiver_id)
        
        # STEP 4: Decrypt message
        decrypted_message = MessageEncryption.decrypt(ciphertext, iv, aes_key)
        
        # STEP 5: Verify signature
        signature_valid = DigitalSignature.verify_signature(
            decrypted_message,
            signature,
            message.sender.public_key_pem
        )
        
        # STEP 6: Verify hash
        hash_valid = HashingUtils.verify_message_hash(decrypted_message, msg_hash, salt)
        
        # Mark as read
        message.is_read = True
        db.session.commit()

        # Add to blockchain audit trail
        audit_chain.add_transaction(
        transaction_type='MESSAGE_EXTRACTED',
        user=user.username,
        details=f"Extracted message #{message_id} from {message.sender.username}"
        )
        audit_chain.mine_pending_transactions()
        
        return render_template('extracted_message.html',
                             message_obj=message,
                             message_text=decrypted_message,
                             signature_valid=signature_valid,
                             hash_valid=hash_valid)
        
    except Exception as e:
        flash(f'Extraction failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:message_id>')
@login_required
def download_image(message_id):
    """Download stego image"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    if not message.can_view(user):
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    
    return send_file(message.stego_image_path, as_attachment=True)

@app.route('/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    """Delete message"""
    message = Message.query.get_or_404(message_id)
    user = User.query.get(session['user_id'])
    
    if not message.can_delete(user):
        flash('Unauthorized: You cannot delete this message', 'error')
        return redirect(url_for('dashboard'))
    
    # Delete image file
    try:
        if os.path.exists(message.stego_image_path):
            os.remove(message.stego_image_path)
    except Exception as e:
        print(f"Error deleting file: {e}")
    
    # Delete from database
    db.session.delete(message)
    db.session.commit()

    # Add to blockchain audit trail
    audit_chain.add_transaction(
    transaction_type='MESSAGE_DELETED',
    user=user.username,
    details=f"Deleted message #{message_id}"
    )
    audit_chain.mine_pending_transactions()
    
    flash('Message deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# ============================================
# INITIALIZE DATABASE
# ============================================

@app.before_request
def create_tables():
    """Create database tables on first request"""
    if not hasattr(app, 'db_initialized'):
        with app.app_context():
            db.create_all()
            
            # Create default users if none exist
            if User.query.count() == 0:
                # Admin user
                admin = User(username='admin', email='admin@stego.com', role='admin')
                admin.set_password('admin123')
                admin.generate_signing_keys()
                
                # Sender user
                sender = User(username='sender', email='sender@stego.com', role='sender')
                sender.set_password('sender123')
                sender.generate_signing_keys()
                
                # Receiver user
                receiver = User(username='receiver', email='receiver@stego.com', role='receiver')
                receiver.set_password('receiver123')
                receiver.generate_signing_keys()
                
                db.session.add_all([admin, sender, receiver])
                db.session.commit()
                
                print("\n" + "="*50)
                print("DEFAULT USERS CREATED:")
                print("Admin: admin / admin123")
                print("Sender: sender / sender123")
                print("Receiver: receiver / receiver123")
                print("="*50 + "\n")
        
        app.db_initialized = True

@app.route('/blockchain')
@login_required
def view_blockchain():
    """View entire blockchain"""
    user = User.query.get(session['user_id'])
    
    # Get blockchain data
    chain = audit_chain.get_chain()
    stats = audit_chain.get_chain_stats()
    
    # Only admins can see full chain
    if user.role != 'admin':
        flash('Only admins can view the full blockchain', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('blockchain.html', 
                         chain=chain, 
                         stats=stats,
                         user=user)

@app.route('/my-audit-log')
@login_required
def my_audit_log():
    """View user's own transactions"""
    user = User.query.get(session['user_id'])
    
    # Get user's transactions
    transactions = audit_chain.get_transactions_by_user(user.username)
    stats = audit_chain.get_chain_stats()
    
    return render_template('my_audit_log.html', 
                         transactions=transactions,
                         stats=stats,
                         user=user)

@app.route('/verify-blockchain')
@login_required
def verify_blockchain():
    """Verify blockchain integrity"""
    is_valid = audit_chain.is_chain_valid()
    stats = audit_chain.get_chain_stats()
    
    if is_valid:
        flash(' Blockchain integrity verified! No tampering detected.', 'success')
    else:
        flash(' WARNING: Blockchain integrity compromised! Tampering detected.', 'error')
    
    return redirect(url_for('view_blockchain'))
# ============================================
# RUN APPLICATION
# ============================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000,use_reloader=False)
    
