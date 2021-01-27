import os
import logging
import re
import sqlite3 as sql
from time import sleep
from datetime import datetime, timedelta
from random import randint

from flask import render_template, g, request, make_response, flash, url_for, session
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from uuid import uuid4

from app import app


load_dotenv()
SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
USERNAME_MIN_LENGTH = int(os.getenv("USERNAME_MIN_LENGTH"))
USERNAME_MAX_LENGTH = int(os.getenv("USERNAME_MAX_LENGTH"))
EMAIL_MIN_LENGTH = int(os.getenv("EMAIL_MIN_LENGTH"))
EMAIL_MAX_LENGTH = int(os.getenv("EMAIL_MAX_LENGTH"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH"))
PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH"))

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[os.getenv("LIMIT_PER_DAY"), os.getenv("LIMIT_PER_MINUTE")]
)
app.secret_key = os.getenv("SECRET_KEY")
logging.basicConfig(level=logging.INFO)


# DB
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sql.connect(os.getenv("DATABASE"))

    try:
        db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, master_password TEXT NOT NULL)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE passwords(id INTEGER PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip_address TEXT NOT NULL, time timestamp)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE resets(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, reset_id TEXT NOT NULL, end_time timestamp)')
    except sql.OperationalError:
        pass
    return db


def query_db(query, values):
    try:
        db = get_db()
        db.cursor().execute(query, values)
        db.commit()
        return True
    except:
        return False


def select_from_db(query, values, mode="one"):
    try:
        if not mode in ["one", "all"]:
            print("Nieprawidłowy tryb")
            return None

        db = get_db()
        if mode == "one":
            rows = db.execute(query, values).fetchone()
        else:
            rows = db.execute(query, values).fetchall()
        return rows
    except:
        return None


@ app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# HOME
@ app.route('/')
def load_home():
    return render_template("home.html")


# REGISTER
@ app.route('/register')
def load_register():
    return render_template("register.html")


@ app.route('/register', methods=['POST'])
def register():
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        flash("Aby zarejestrować się, musisz wypełnić wszystkie pola!")
        return redirect('load_register')

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    password1 = request.form.get('password1')
    master_password = request.form.get('master_password')
    master_password1 = request.form.get('master_password1')

    if len(username) < USERNAME_MIN_LENGTH:
        flash("Nazwa użytkownika jest zbyt krótka")
        return redirect('load_register')
    if len(username) > USERNAME_MAX_LENGTH:
        flash("Nazwa użytkownika jest zbyt długa")
        return redirect('load_register')
    if not re.match('^[a-z]+$', username):
        flash("Nazwa użytkownika może składać się tylko z małych liter!")
        return redirect('load_register')

    if len(email) < EMAIL_MIN_LENGTH:
        flash("Email jest zbyt krótki")
        return redirect('load_register')
    if len(email) > EMAIL_MAX_LENGTH:
        flash(f"Email nie może być dłuższy niż {EMAIL_MAX_LENGTH} znaków")
        return redirect('load_register')
    if not re.search('[^@]+@[^@]+\.[^@]+', email):
        flash("Niepoprawny email, popraw go i spróbuj ponownie!")
        return redirect('load_register')

    if not is_password_safe(password, "Hasło"):
        return redirect('load_register')
    if password != password1:
        flash("Podane hasła nie pasują do siebie!")
        return redirect('load_register')

    if not is_password_safe(master_password, "Hasło główne"):
        return redirect('load_register')
    if master_password != master_password1:
        flash("Podane hasła główne nie pasują do siebie!")
        return redirect('load_register')

    if username and email and password and password1 and master_password and master_password1:
        if is_registred(username):
            flash(f"Niepoprawna nazwa użytkownika, popraw ją i spróbuj ponownie")
            return redirect('load_register')

        hashed = prepare_password(password)
        master_hashed = prepare_password(master_password)
        is_success = query_db('INSERT INTO users (username, email, password, master_password) VALUES (?, ?, ?, ?)', [
            username, email, hashed, master_hashed])
        if not is_success:
            flash(f"Podczas rejestracji wystąpił błąd! Spróbuj ponownie później.")
            return redirect('load_register')
        return redirect('load_login')


def is_password_safe(password, password_type):
    if not password:
        flash(f"{password_type} nie może być puste!")
        return False
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(f"{password_type} musi mieć conajmniej {PASSWORD_MIN_LENGTH} znaków!")
        return False
    if len(password) > PASSWORD_MAX_LENGTH:
        flash(f"{password_type} jest zbyt długie!")
        return False
    regex = ("^(?=.*[a-z])(?=." + "*[A-Z])(?=.*\\d)" +
             "(?=.*[-+_!@#$%^&*., ?]).+$")
    if not re.search(re.compile(regex), password):
        flash(f"{password_type} musi składać się przynajmniej: z jednej dużej litery, z jednego małego znaku, z jednej cyfry oraz z jednego znaku specjalnego!")
        return False
    return True


def is_registred(username):
    res = select_from_db('SELECT id FROM users WHERE username = ?', [username])
    return res != None


def prepare_password(password, salt_length=SALT_LENGTH):
    password, salt = password.encode(),  gensalt(salt_length)
    return hashpw(password, salt)


def redirect(destination_name, status=302):
    response = make_response('', status)
    response.headers['Location'] = url_for(destination_name)
    return response


# LOGIN
@ app.route('/login')
def load_login():
    return render_template("login.html")


@ app.route('/login', methods=['POST'])
def login():
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        flash("Nazwa użytkownika ani hasło nie może być puste!")
        wait_some_time()
        return redirect('load_login')

    username = request.form.get('username')
    password = request.form.get('password')
    if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH:
        flash("Podano niepoprawną nazwę użytkownika!")
        wait_some_time()
        return redirect('load_login')
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        flash("Podano niepoprawne hasło!")
        wait_some_time()
        return redirect('load_login')

    if is_registred(username):
        password = password.encode()
        res = select_from_db(
            'SELECT password FROM users WHERE username = ?', [username])
        hashed = res[0]
        if hashed:
            if checkpw(password, hashed):
                # Użytkownik się zalogował
                flash(f"Witaj z powrotem {username}")
                session["username"] = username
                session["logged-at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
                return redirect('load_dashboard')
            else:
                # Użytkownik się pomylił, albo przeprowadzono atak na niego
                query_db('INSERT INTO attempts (username, ip_address, time) VALUES (?, ?, ?);', [
                    username, get_remote_address(), datetime.now()])
                wait_some_time()
                return redirect('load_login')
    else:
        # Użytkownika nie ma w db
        flash("Nieprawidłowe dane logowania!")
        wait_some_time()
        return redirect('load_login')


def wait_some_time(l1=200, l2=900):
    d = randint(l1, l2)/1000
    sleep(d)


# RESET
@ app.route('/reset')
@ limiter.exempt
def load_reset():
    return render_template("reset.html")


@ app.route('/reset', methods=['POST'])
def handle_reset_request():
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        flash("Email nie może być pusty!")
        return redirect('load_reset')

    email = request.form.get('email')
    if len(email) < EMAIL_MIN_LENGTH or len(email) > EMAIL_MAX_LENGTH:
        flash("Niepoprawny email, popraw go i spróbuj ponownie!")
        return redirect('load_reset')
    if not re.search('[^@]+@[^@]+\.[^@]+', email):
        flash("Niepoprawny email, popraw go i spróbuj ponownie!")
        return redirect('load_reset')

    if is_in_db(email):
        if is_resetting(email):
            flash("Niepoprawny email, popraw go i spróbuj ponownie!")
            return redirect('load_reset')

        reset_id = uuid4().hex + uuid4().hex  # secrets.token_hex(60)
        experience_date = datetime.utcnow() + timedelta(hours=24)
        is_success = query_db('INSERT INTO resets (email, reset_id, end_time) VALUES (?, ?, ?);', [
            email, reset_id, experience_date])
        if is_success:
            reset_link = url_for('handle_reset_request') + '/' + reset_id
            send_link_to_user_via_email(email, reset_link)
            flash("Link do zresetowania hasła został wysłany na twój email!")
            return redirect('load_reset')
        else:
            flash("Podczas resetowania hasła wystąpił błąd!")
            return redirect('load_reset')
    else:
        flash("Na podany adres email wysłano link do zresetowania hasła.")
        return redirect('load_reset')


def is_in_db(email):
    res = select_from_db(
        "SELECT id FROM users WHERE email = ?", [email])
    return res != None


def is_resetting(email):
    res = select_from_db(
        "SELECT id FROM resets WHERE email = ?", [email])
    print(res)
    return res != None


def send_link_to_user_via_email(email, reset_link):
    logging.info(f'Wysyłam link {reset_link} pod {email}')
    # TODO


# USER CHANGES PASSWORD
@ app.route('/reset/<reset_id>', methods=['GET'])
def load_reset_with_token(reset_id):
    if is_allowed(reset_id) and is_valid(reset_id):
        return render_template("reset_with_token.html")
    else:
        return "", 401


def is_allowed(reset_id):
    res = select_from_db(
        "SELECT id FROM resets WHERE reset_id = ?", [reset_id])
    return res != None


def is_valid(reset_id):
    res = select_from_db(
        "SELECT end_time FROM resets WHERE reset_id = ?", [reset_id])
    if res != None:
        experience_date = datetime.strptime(res[0], '%Y-%m-%d %H:%M:%S.%f')
        now = datetime.now()
        diff = experience_date - now
        days, seconds = diff.days, diff.seconds
        hours = days * 24 + seconds // 3600

        if hours > 0:
            return True
        else:
            return False
    else:
        return False


@ app.route('/reset/<reset_id>', methods=['POST'])
def reset_password(reset_id):
    if not is_allowed(reset_id):
        flash("Wystąpił błąd!")
        return redirect('load_home')
    if not is_valid(reset_id):
        flash("Wystąpił błąd!")
        query_db(
            'DELETE FROM resets WHERE reset_id = ?', [reset_id])
        return redirect('load_home')

    res = select_from_db(
        "SELECT email FROM resets WHERE reset_id = ?", [reset_id])
    if res == None:
        flash("Wystąpił błąd!")
        return redirect('load_home')

    email = res[0]
    password = request.form.get('password')
    password1 = request.form.get('password1')
    if not is_password_safe(password, "Hasło"):
        return redirect('reset_password' + '/' + reset_id)
    if password != password1:
        flash("Podane hasła nie pasują do siebie!")
        return redirect('reset_password' + '/' + reset_id)

    hashed = prepare_password(password)
    is_success = query_db(
        'UPDATE users SET password = ? WHERE email = ?', [hashed, email])
    if not is_success:
        flash(f"Podczas zmiany hasła wystąpił błąd! Spróbuj ponownie później.")
        return redirect('load_home')
    is_success = query_db(
        'DELETE FROM resets WHERE reset_id = ?', [reset_id])
    if not is_success:
        flash(f"Podczas zmiany hasła wystąpił błąd! Spróbuj ponownie później.")
        return redirect('load_home')

    flash(f"Twoje hasło zostało zmienione")
    return redirect('load_login')


# DASHBOARD
@ app.route('/dashboard')
def load_dashboard():
    # TODO
    return


# LOGOUT
@ app.route('/logout')
def load_logout():
    # TODO
    return


# PASSWORDS
@ app.route('/passes', methods=["GET"])
def load_passwords():
    # TODO
    return


@ app.route('/passes', methods=["POST"])
def add_pass():
    # TODO
    return


@ app.route('/passes/master', methods=["POST"])
def get_pass():
    # TODO
    return
