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
from .models.validation import Validator
from .db.db_manager import DbManager


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

db = DbManager()
v = Validator()

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[os.getenv("LIMIT_PER_DAY"), os.getenv("LIMIT_PER_MINUTE")]
)
app.secret_key = os.getenv("SECRET_KEY")
logging.basicConfig(level=logging.INFO)

""" 
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
        return None """

@ app.teardown_appcontext
def close_connection(exception):
    d = getattr(g, '_database', None)
    if d is not None:
        d.close()


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
    if v.is_empty(request.form):
        return redirect('load_reset')

    email = request.form.get('email')
    if not v.is_email_valid(email):
        return redirect('load_reset')

    if db.is_email_registered(email):
        if db.is_resetting_already(email):
            flash("Niepoprawny email, popraw go i spróbuj ponownie!")
            return redirect('load_reset')

        reset_id = uuid4().hex + uuid4().hex
        experience_date = datetime.utcnow() + timedelta(hours=24)
        if db.save_reset_request(email, reset_id, experience_date):
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


def send_link_to_user_via_email(email, reset_link):
    logging.info(f'Wysyłam link {reset_link} pod {email}')
    # TODO


# USER CHANGES PASSWORD
@ app.route('/reset/<reset_id>', methods=['GET'])
def load_reset_with_token(reset_id):
    if db.is_allowed_for_resetting(reset_id) and db.is_reset_link_valid(reset_id):
        return render_template("reset_with_token.html")
    else:
        return "", 401


@ app.route('/reset/<reset_id>', methods=['POST'])
def reset_password(reset_id):
    if not db.is_allowed_for_resetting(reset_id):
        flash("Wystąpił błąd!")
        return redirect('load_home')
    if not db.is_reset_link_valid(reset_id):
        db.delete_reset_link(reset_id)
        flash("Wystąpił błąd!")
        return redirect('load_home')

    res = db.get_email_with_reset_id(reset_id)
    if res == None:
        flash("Wystąpił błąd!")
        return redirect('load_home')

    email = res[0]
    password = request.form.get('password')
    password1 = request.form.get('password1')

    if not v.is_passwords_safe(password, password1, ""):
        return redirect('reset_password' + '/' + reset_id)

    hashed = hash_pass(password)
    if not db.change_user_password(email, hashed):
        flash(f"Podczas zmiany hasła wystąpił błąd! Spróbuj ponownie później.")
        return redirect('load_home')
    db.delete_reset_link(reset_id)
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

    res = db.get_user_passwords(username) 
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
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    name = request.form.get("new-name")
    password = request.form.get("new-password")
    master_password = request.form.get("master-pass")

    if not v.is_service_name_valid(name) or not v.is_password_safe(password, "") or not v.is_password_safe(master_password, "główne"):
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        password = encrypt_password(password, master_password)
        if db.add_user_password(username, name, password):
            return "Dodano nowe hasło", 201
        else:
            return ERROR_MESSAGE, 400
    else:
        return ERROR_MESSAGE, 401


def verify_master(username, master_password):
    master_password = master_password.encode()
    res = db.get_user_master_password(username)
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
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    service_name = request.form.get("master-name")
    master_password = request.form.get("master-password")
    if not v.is_service_name_valid(service_name) or not v.is_password_safe(master_password, ""):
        return ERROR_MESSAGE, 400
    
    if verify_master(username, master_password):
        res = db.get_user_pass(username, service_name)
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
