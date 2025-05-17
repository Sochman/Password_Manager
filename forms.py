# Importy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Regexp, Length
import hashlib
import requests

# Reguła siły hasła: co najmniej 8 znaków, wielka, mała litera, cyfra, znak specjalny
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'

def is_password_pwned(password: str) -> bool:
    """
    Sprawdza, czy podane hasło zostało ujawnione w publicznych wyciekach danych
    (usługa Have I Been Pwned – API k-anonimowe).

    Zasada działania:
    - Hasło jest haszowane SHA1.
    - Do API wysyłane jest tylko 5 pierwszych znaków (prefix).
    - Odpowiedź zawiera wszystkie końcówki pasujące do prefixu.
    - Jeśli pełny hash istnieje na liście – hasło uznajemy za niebezpieczne.

    Bezpieczeństwo:
    - Nie wysyłamy pełnego hasła (ani nawet jego pełnego SHA1).
    - Jeśli API nie odpowiada, nie blokujemy użytkownika.

    :param password: Hasło w formie tekstowej (przed haszowaniem).
    :return: True, jeśli hasło znajduje się w wycieku. False w przeciwnym razie.
    """
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        if response.status_code != 200:
            return False  # nie blokuj rejestracji, jeśli API nie działa

        for line in response.text.splitlines():
            hash_suffix, _ = line.split(':')
            if hash_suffix == suffix:
                return True  # hasło wyciekło – należy je odrzucić

    except requests.RequestException:
        return False   # API niedostępne – nie blokujemy użytkownika

    return False  # hasło nie znalezione w wyciekach

class RegistrationForm(FlaskForm):
    """
    Formularz rejestracji użytkownika.
    Sprawdza poprawność e-maila, siłę hasła oraz czy hasło nie znajduje się w znanych wyciekach.
    """
    email = StringField(
        'E-mail',
        validators=[
            DataRequired(message="E-mail jest wymagany."),
            Email(message="Nieprawidłowy format e-mail."),
        ]
    )
    password = PasswordField(
        'Hasło',
        validators=[
            DataRequired(message="Hasło jest wymagane."),
            Regexp(
                PASSWORD_REGEX,
                message=(
                    "Hasło musi mieć min. 8 znaków, zawierać co najmniej "
                    "jedną wielką literę, jedną małą, cyfrę i znak specjalny."
                )
            )
        ]
    )
    password_confirm = PasswordField(
        'Powtórz hasło',
        validators=[
            DataRequired(message="Potwierdzenie hasła jest wymagane."),
            EqualTo('password', message="Hasła nie są zgodne.")
        ]
    )
    submit = SubmitField('Zarejestruj się')

    def validate_password(self, field):
        """
        Weryfikacja hasła przy rejestracji z użyciem HIBP API.
        """
        if is_password_pwned(field.data):
            raise ValidationError("To hasło pojawiło się w znanym wycieku danych - wybierz inne.")

class LoginForm(FlaskForm):
    """
    Formularz logowania użytkownika.
    Podstawowa walidacja obecności danych i formatu e-mail.
    """
    email = StringField(
        'E-mail',
        validators=[
            DataRequired(message="E-mail jest wymagany."),
            Email(message="Nieprawidłowy format e-mail."),
                ]
    )
    password = PasswordField(
        'Hasło',
        validators=[DataRequired(message="Hasło jest wymagane.")]
    )

    submit = SubmitField('Zaloguj się')

class ChangePasswordForm(FlaskForm):
    """
    Formularz zmiany hasła:
    - wymaga starego hasła
    - nowe hasło musi spełniać kryteria bezpieczeństwa
    - nowe hasło nie może być z wycieków (HIBP)
    - hasła muszą się zgadzać (potwierdzenie)
    """
    old_password = PasswordField("Stare hasło", validators=[DataRequired()])
    new_password = PasswordField("Nowe hasło", validators=[
        DataRequired(),
        Regexp(
            PASSWORD_REGEX,
            message=(
                "Hasło musi mieć min. 8 znaków, zawierać wielką literę, małą, cyfrę i znak specjalny."
            )
        )
    ])
    confirm_new_password = PasswordField("Potwierdź nowe hasło", validators=[
        DataRequired(),
        EqualTo('new_password', message="Hasła nie są zgodne.")
    ])
    submit = SubmitField("Zmień hasło")

    def validate_new_password(self, field):
        """
        Dodatkowa walidacja nowego hasła z użyciem HIBP.
        """
        if is_password_pwned(field.data):
            raise ValidationError("To hasło pojawiło się w znanym wycieku danych - wybierz inne.")

class TwoFactorForm(FlaskForm):
    """
    Formularz kodu TOTP dla 2FA (Google/Microsoft Authenticator).
    Kod musi być 6-cyfrowy.
    """
    code = StringField(
        "Kod 2FA",
        validators=[
            DataRequired(message="Wpisz kod z aplikacji uwierzytelniającej."),
            Length(min=6, max=6, message="Kod musi mieć dokładnie 6 cyfr.")
        ]
    )
    submit = SubmitField("Zweryfikuj")