# Importy
import os
import sqlite3
from pathlib import Path
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    g,
    request,
    )
import pyotp
import qrcode
import base64

from io import BytesIO
from cryptography.fernet import Fernet
from functools import wraps
from dotenv import load_dotenv
from passlib.hash import argon2
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from forms import RegistrationForm, LoginForm, ChangePasswordForm, TwoFactorForm

# Inicjalizacja struktury bazy danych (jeśli to pierwszy uruchomienie)
load_dotenv(Path(__file__).parent / '.env')

class Config:
    """
    Konfiguracja aplikacji Flask
    """
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY musi być ustawiony w pliku .env")

    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'users.db')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_ENABLED = True


def get_db():
    """
    Zwraca połączenie z bazą danych w kontekście aplikacji.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            Config.DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """
    Zamyka połączenie z bazą danych po zakończeniu żądania.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """
    Inicjalizuje tabelę `users` jeśli jeszcze nie istnieje.
    """
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 0,
            totp_secret TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """
    )
    db.commit()

def login_required(view_func):
    """
    Dekorator sprawdzający, czy użytkownik jest zalogowany (sesja zawiera `user_email`).
    W przeciwnym razie przekierowuje do logowania.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            flash("Musisz być zalogowany, aby zobaczyć tę stronę.", "warning")
            return redirect(url_for('login', next=request.url))
        return view_func(*args, **kwargs)
    return wrapper

# Inicjalizacja narzędzia do szyfrowania TOTP
fernet = Fernet(os.environ['TOTP_ENCRYPTION_KEY'])
def encrypt_totp_secret(secret: str) -> str:
    """Szyfruje sekret TOTP przed zapisaniem do bazy."""
    return fernet.encrypt(secret.encode()).decode()

def decrypt_totp_secret(token: str) -> str:
    """Deszyfruje sekret TOTP z bazy danych."""
    return fernet.decrypt(token.encode()).decode()

# --- Flask App Factory ---

def create_app():
    """
    Tworzy instancję aplikacji Flask wraz z konfiguracją, rate limitingiem, CSRF, DB.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ochrona formularzy przed atakami CSRF (Cross-Site Request Forgery)
    CSRFProtect(app)

    # Limitowanie liczby żądań: domyślnie 200 dziennie i 50 na godzinę na IP
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    limiter.init_app(app)

    # Automatyczne zamykanie połączenia z bazą po każdym żądaniu
    app.teardown_appcontext(close_db)

    # Inicjalizacja  bazy danych (jeśli to pierwsze uruchomienie)
    with app.app_context():
        init_db()

    @app.route('/')
    def index():
        """
        Przekierowanie z root ('/') do logowania.
        """
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")  # Limit registration attempts
    def register():
        """
        Rejestracja użytkownika z weryfikacją danych i MFA.
        """
        if 'user_email' in session:
            return redirect(url_for('dashboard'))
        form = RegistrationForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            pw_hash = argon2.hash(form.password.data)
            try:
                db = get_db()
                # Usuwanie nieaktywnego konta, jeśli istnieje
                db.execute(
                    "DELETE FROM users WHERE email = ? AND is_active = 0",
                    (email,)
                )
                db.execute(
                    "INSERT INTO users (email, password_hash, is_active) VALUES (?, ?, 0)",
                    (email, pw_hash)
                )
                db.commit()
                session['pending_mfa_registration'] = email
                flash("Rejestracja zakończona – skonfiguruj MFA.", "info")
                return redirect(url_for('register_mfa'))
            except sqlite3.IntegrityError:
                flash("Podany e-mail jest już zarejestrowany.", "danger")
                
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")  # Limit login attempts
    def login():
        """
        Logowanie użytkownika i przekierowanie do weryfikacji 2FA.
        """
        if 'user_email' in session:
            return redirect(url_for('dashboard'))
        
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            pw = form.password.data
            user = get_db().execute(
                "SELECT password_hash, is_active FROM users WHERE email = ?", 
                (email,)
            ).fetchone()
            if user and argon2.verify(pw, user['password_hash']):
                if user['is_active'] != 1:
                    flash("Musisz ponownie zarejestrować konto - nieskonfigurowano MFA.", "warning")
                    return redirect(url_for('login'))   
                session.clear()
                session['pending_2fa'] = email
                return redirect(url_for('twofa_verify'))
            else:
                flash("Nieprawidłowy e-mail lub hasło.", "danger")
        return render_template('login.html', form=form)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        """
        Widok główny (dashboard) dostępny tylko po zalogowaniu.
        """
        return render_template('dashboard.html', email=session['user_email'])
    
    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        """
        Zmiana hasła użytkownika z walidacją HIBP i siły hasła.
        """
        form = ChangePasswordForm()
        email = session['user_email']
        user = get_db().execute(
            "SELECT password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        if form.validate_on_submit():
            if not argon2.verify(form.old_password.data, user['password_hash']):
                flash("Stare hasło jest nieprawidłowe.", "danger")
            elif argon2.verify(form.new_password.data, user['password_hash']):
                flash("Nowe hasło nie może być takie samo jak obecne.", "warning")
            else:
                new_hash = argon2.hash(form.new_password.data)
                db = get_db()
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE email = ?",
                    (new_hash, email)
                )
                db.commit()
                flash("Hasło zostało zmienione.", "success")
                return redirect(url_for('dashboard'))

        return render_template('change_password.html', form=form)

    @app.route('/register-mfa', methods=['GET', 'POST'])
    def register_mfa():
        """
        Konfiguracja MFA z generowaniem QR i walidacją kodu.
        """
        if 'pending_mfa_registration' not in session:
            flash("Dostęp do konfiguracji MFA wygasł.", "warning")
            return redirect(url_for('register'))

        email = session['pending_mfa_registration']
        db = get_db()

        # Sekret MFA tymczasowo w sesji
        if 'temp_totp_secret' not in session:
            secret = pyotp.random_base32()
            session['temp_totp_secret'] = secret
        else:
            secret = session['temp_totp_secret']

        # Tworzymy provisioning URI
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name="MojaAplikacja"
        )

        # Generujemy QR kod (Base64)
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format='PNG')
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()

        form = TwoFactorForm()

        if form.validate_on_submit():
            totp = pyotp.TOTP(secret)
            if totp.verify(form.code.data):
                encrypted_secret = encrypt_totp_secret(secret)
                db.execute(
                    "UPDATE users SET totp_secret = ?, is_active = 1 WHERE email = ?",
                    (encrypted_secret, email)
                )
                db.commit()
                session.clear()
                flash("MFA skonfigurowane. Możesz się teraz zalogować.", "success")
                return redirect(url_for('login'))
            else:
                flash("Nieprawidłowy kod. Spróbuj ponownie.", "danger")

        return render_template('register_mfa.html', form=form, qr_b64=qr_b64)


    @app.route('/2fa-verify', methods=['GET', 'POST'])
    def twofa_verify():
        """
        Weryfikacja kodu 2FA po poprawnym logowaniu hasłem.
        """
        if 'pending_2fa' not in session:
            flash("Brak autoryzacji. Zaloguj się ponownie.", "warning")
            return redirect(url_for('login'))

        email = session['pending_2fa']
        db = get_db()
        user = db.execute(
            "SELECT totp_secret FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user or not user['totp_secret']:
            flash("Brak skonfigurowanego MFA. Skontaktuj się z administratorem.", "danger")
            return redirect(url_for('login'))

        secret = decrypt_totp_secret(user['totp_secret'])
        totp = pyotp.TOTP(secret)

        form = TwoFactorForm()

        if form.validate_on_submit():
            if totp.verify(form.code.data):
                db.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = ?",
                    (email,)
                )
                db.commit()
                session.clear()
                session['user_email'] = email
                session.modified = True
                return redirect(url_for('dashboard'))
            else:
                flash("Nieprawidłowy kod 2FA.", "danger")

        return render_template("twofa_verify.html", form=form)

    @app.route('/logout')
    def logout():
        """
        Wylogowanie użytkownika (czyszczenie sesji).        
        """
        session.clear()
        flash("Zostałeś wylogowany.", "info")
        return redirect(url_for('login'))

    return app


if __name__ == '__main__':
    # Uruchomienie aplikacji w trybie developerskim
    app = create_app()
    app.run()