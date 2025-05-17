# Password Manager (Flask)

Bezpieczna aplikacja webowa do zarządzania kontami użytkowników z obsługą:

- ✅ Rejestracji i logowania
- ✅ Weryfikacji dwuetapowej (2FA) przez TOTP (np. Google/Microsoft Authenticator)
- ✅ Sprawdzenia bezpieczeństwa hasła w bazie Have I Been Pwned (HIBP)
- ✅ Zmiany hasła
- ✅ Ochrony przed atakami CSRF i brute-force (rate-limiting)

---

## 🔧 Wymagania

- Python 3.9+
- SQLite
- Virtualenv (zalecane)

## 📦 Instalacja

```bash
git clone https://github.com/Sochman/Password_Manager.git
cd Password_Manager
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
