import os
import logging
import re
import sqlite3 as sql

from flask import render_template,  g, request, make_response, flash, url_for
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw

from app import app


load_dotenv()
SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
USERNAME_MIN_LENGTH = int(os.getenv("USERNAME_MIN_LENGTH"))
USERNAME_MAX_LENGTH = int(os.getenv("USERNAME_MAX_LENGTH"))
EMAIL_MIN_LENGTH = int(os.getenv("EMAIL_MIN_LENGTH"))
EMAIL_MAX_LENGTH = int(os.getenv("EMAIL_MAX_LENGTH"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH"))
PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH"))

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
    # TODO
    return


@ app.route('/login', methods=['POST'])
def login():
    # TODO
    return


# RESET
@ app.route('/reset')
def load_reset():
    # TODO
    return


@ app.route('/reset', methods=['POST'])
def handle_reset_request():
    # TODO
    return


# USER CHANGES PASSWORD
@ app.route('/reset/<reset_id>', methods=['GET'])
def load_reset_with_token(reset_id):
    # TODO
    return


@ app.route('/reset/<reset_id>', methods=['POST'])
def reset_password(reset_id):
    # TODO
    return


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
