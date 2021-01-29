import os
import logging
import re
import sqlite3 as sql
from time import sleep
from datetime import datetime, timedelta
from random import randint

from flask import render_template, g, request, make_response, flash, url_for, session, jsonify
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from uuid import uuid4

from app import app
from .models.aes import AESCipher
import validation as v
import db_manager as db


load_dotenv()
SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
USERNAME_MIN_LENGTH = int(os.getenv("USERNAME_MIN_LENGTH"))
USERNAME_MAX_LENGTH = int(os.getenv("USERNAME_MAX_LENGTH"))
EMAIL_MIN_LENGTH = int(os.getenv("EMAIL_MIN_LENGTH"))
EMAIL_MAX_LENGTH = int(os.getenv("EMAIL_MAX_LENGTH"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH"))
PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH"))
SERVICE_NAME_MIN_LENGTH = int(os.getenv("SERVICE_NAME_MIN_LENGTH"))
SERVICE_NAME_MAX_LENGTH = int(os.getenv("SERVICE_NAME_MAX_LENGTH"))

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
    if v.is_empty(request.form):
        return redirect('load_register')

    user = {}
    for n in ['username', 'email', 'password', 'password1', 'master_password', 'master_password1']:
        user[n] = request.form.get(n)

    if not v.is_user_valid(user):
        return redirect('load_register')

    hashed, mhashed = hash_pass(user['password']), hash_pass(user['master'])
    if not db.register_user(user['username'], user['email'], hashed, mhashed):
        flash(f"Podczas rejestracji wystąpił błąd! Spróbuj ponownie później.")
        return redirect('load_register')
    return redirect('load_login')


def redirect(destination_name, status=302):
    response = make_response('', status)
    response.headers['Location'] = url_for(destination_name)
    return response


def hash_pass(password, salt_length=SALT_LENGTH):
    password, salt = password.encode(),  gensalt(salt_length)
    return hashpw(password, salt)


# LOGIN
@ app.route('/login')
def load_login():
    return render_template("login.html")


@ app.route('/login', methods=['POST'])
def login():
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        handle_wrong_login("Nazwa użytkownika ani hasło nie może być puste!")

    username = request.form.get('username')
    password = request.form.get('password')
    if v.is_username_login_valid(username):
        handle_wrong_login("Podano niepoprawną nazwę użytkownika!")
    if v.is_password_login_valid(password):
        handle_wrong_login("Podano niepoprawne hasło!")

    if db.is_registred(username):
        password = password.encode()
        hashed = db.get_user_password(username)
        if hashed:
            if checkpw(password, hashed):
                flash(f"Witaj z powrotem {username}")
                session["username"] = username
                session["logged-at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
                return redirect('load_dashboard')
            else:
                db.save_attempt(username, get_remote_address(), datetime.now())
                return handle_wrong_login("Nieprawidłowe dane logowania!")
    else:
        return handle_wrong_login("Nieprawidłowe dane logowania!")


def handle_wrong_login(msg):
    flash(msg)
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
        # if save_reset_request(email, reset_id, experience_date):
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
    # if is_allowed_for_resetting(reset_id) and is_reset_link_valid(reset_id):
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
@ limiter.exempt
def load_dashboard():
    username = session.get("username")
    if username:
        return render_template('dashboard.html')
    else:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login')


# LOGOUT
@ app.route('/logout')
@ limiter.exempt
def load_logout():
    session.clear()
    return redirect('load_home')


# PASSWORDS
@ app.route('/passes', methods=["GET"])
def load_passwords():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    res = select_from_db(
        'SELECT name FROM passwords WHERE username = ?', [username], "all")

    response = {}
    if res != None:
        passes = []
        for r in res:
            p = {}
            p['name'] = r[0]
            passes.append(p)
        response['passes'] = passes
    else:
        return "Podczas pobierania wystąpił błąd!", 400
    return jsonify(response), 200


@ app.route('/passes', methods=["POST"])
def add_pass():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas dodawania wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        return ERROR_MESSAGE, 400

    name = request.form.get("new-name")
    password = request.form.get("new-password")
    master_password = request.form.get("master-pass")

    if len(name) < SERVICE_NAME_MIN_LENGTH or len(name) > SERVICE_NAME_MAX_LENGTH or len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH or len(master_password) < PASSWORD_MIN_LENGTH or len(master_password) > PASSWORD_MAX_LENGTH:
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        password = encrypt_password(password, master_password)
        q = 'INSERT INTO passwords (username, name, password) VALUES (?, ?, ?)'
        v = [username, name, password]
        if query_db(q, v):
            return "Dodano nowe hasło", 201
        else:
            return ERROR_MESSAGE, 400
    else:
        return ERROR_MESSAGE, 401


def verify_master(username, master_password):
    master_password = master_password.encode()
    res = select_from_db(
        'SELECT master_password FROM users WHERE username = ?', [username])
    if res != None:
        hashed = res[0]
        if hashed:
            return checkpw(master_password, hashed)
    return False


def encrypt_password(password, master_password):
    c = AESCipher(key=master_password)
    return c.encrypt(password)


@ app.route('/passes/master', methods=["POST"])
def get_pass():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas odszyfrowywania wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    empty_fields = [f for f in request.form.values() if not f]
    if len(empty_fields) != 0:
        return ERROR_MESSAGE, 400

    service_name = request.form.get("master-name")
    master_password = request.form.get("master-password")

    if len(service_name) < SERVICE_NAME_MIN_LENGTH or len(service_name) > SERVICE_NAME_MAX_LENGTH or len(master_password) < PASSWORD_MIN_LENGTH or len(master_password) > PASSWORD_MAX_LENGTH:
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        res = select_from_db(
            'SELECT password FROM passwords WHERE username = ? AND name = ?', [username, service_name])
        if res != None:
            response = {}
            response['pass'] = decrypt_password(master_password, res[0])
            return jsonify(response), 200
        else:
            return ERROR_MESSAGE, 400
    else:
        return ERROR_MESSAGE, 401


def decrypt_password(master_password, password):
    c = AESCipher(key=master_password)
    return c.decrypt(password)
