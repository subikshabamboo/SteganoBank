# decorators.py
from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    """Ensure user is logged in with MFA"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('auth.login'))
        
        if not session.get('mfa_verified', False):
            flash('Please complete MFA verification', 'error')
            return redirect(url_for('auth.verify_mfa'))
        
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    """Ensure user has required role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                flash('Please login first', 'error')
                return redirect(url_for('login'))
            
            if session['role'] not in roles:
                flash('Unauthorized access', 'error')
                return redirect(url_for('main.dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator