import os
import logging
import re
import sqlite3 as sql
from time import sleep
from datetime import datetime, timedelta
from random import randint
import string
import secrets

from flask import render_template, g, request, make_response, flash, url_for, session, jsonify, Response
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from uuid import uuid4

from app import app
from .models.aes import AESCipher
from .models.validation import Validator
from .db.db_manager import DbManager
from fpdf import FPDF


db, v = DbManager(), Validator()

load_dotenv()
SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
LIMIT_PER_DAY = os.getenv("LIMIT_PER_DAY")
LIMIT_PER_MINUTE = os.getenv("LIMIT_PER_MINUTE")
SECRET_KEY = os.getenv("SECRET_KEY")

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[LIMIT_PER_DAY, LIMIT_PER_MINUTE]
)
app.secret_key = SECRET_KEY
logging.basicConfig(level=logging.INFO)


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

    hashed, mhashed = hash_pass(
        user['password']), hash_pass(user['master_password'])
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
    if v.is_empty(request.form):
        handle_wrong_login("Nazwa użytkownika ani hasło nie może być puste!")

    username = request.form.get('username')
    password = request.form.get('password')
    if not v.is_username_login_valid(username):
        handle_wrong_login("Podano niepoprawną nazwę użytkownika!")
    if not v.is_password_login_valid(password):
        handle_wrong_login("Podano niepoprawne hasło!")

    if db.is_registred(username):
        password = password.encode()
        hashed = db.get_user_password(username)
        if hashed:
            if checkpw(password, hashed):
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
    if not session.get("username"):
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login')
    return render_template('dashboard.html')


# DASHBOARD INFO
@ app.route('/dashboardi')
@ limiter.exempt
def load_dashboardi():
    if not session.get("username"):
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login')
    return render_template('dashboardi.html')


# REPORT
@ app.route('/report')
@ limiter.exempt
def load_report():
    if not session.get("username"):
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login')

    # Nie wolno dodawać polskich znaków do PDF bo inaczej latin-1 się wywróci
    REPORT_TITLE = "Twoje Serwisy"

    res = db.get_user_passwords(session.get("username"))
    if res != None:
        pdf = FPDF()
        pdf.add_page()
        page_width = pdf.w - 2 * pdf.l_margin
        pdf.set_font('Times', 'B', 14.0)
        pdf.cell(page_width, 0.0, REPORT_TITLE, align='C')
        pdf.ln(10)
        pdf.set_font('Courier', '', 12)
        col_width = page_width/4
        pdf.ln(1)
        th = pdf.font_size

        for r in res:
            service_name = r[0]
            pdf.cell(col_width, th, service_name, border=1)
            pdf.ln(th)

        pdf.ln(10)
        pdf.set_font('Times', '', 10.0)
        if len(res) != 0:
            pdf.cell(page_width, 0.0, f"- {len(res)} hasel -", align='C')
        else:
            pdf.cell(page_width, 0.0, "--- Brak Zapisanych Hasel ---", align='C')

        return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=report.pdf'})
    else:
        return "Podczas pobierania wystąpił błąd!", 400


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


@ app.route('/passes/master', methods=["POST"])
def decrypt_pass():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas odszyfrowywania wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    service_name = request.form.get("decrypt-name")
    master_password = request.form.get("decrypt-master")
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


@ app.route('/passes', methods=["POST"])
def add_pass():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas dodawania wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    name = request.form.get("add-name")
    password = request.form.get("add-password")
    master_password = request.form.get("add-master")

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


@ app.route('/passes', methods=["PUT"])
def change_pass():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas zmiany hasła wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    name = request.form.get("change-name")
    password = request.form.get("change-password")
    master_password = request.form.get("change-master")

    if not v.is_service_name_valid(name) or not v.is_password_safe(password, "") or not v.is_password_safe(master_password, "główne"):
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        password = encrypt_password(password, master_password)
        if db.change_user_pass(username, name, password):
            now = datetime.now()
            db.insert_password_to_history(username, name, password, now)
            return "Hasło zostało zmienione", 200
        else:
            return ERROR_MESSAGE, 400
    else:
        return ERROR_MESSAGE, 400


# HISTORY
@ app.route('/history', methods=["POST"])
def load_history():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas pobierania historii hasła wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400
    service_name = request.form.get("show-name")
    master_password = request.form.get("show-master")

    if not v.is_service_name_valid(service_name) or not v.is_password_safe(master_password, "główne"):
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        res = db.get_password_history(username, service_name)
        response = {}
        if res != None:
            history = []
            for r in res:
                h = {}
                h['password'] = decrypt_password(master_password, r[0])
                h['time'] = r[1]
                history.append(h)
            response['history'] = history
        return jsonify(response), 200
    else:
        return ERROR_MESSAGE, 400


# INFO
@ app.route('/info/<service_name>', methods=["GET"])
def load_info(service_name):
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas pobierania informacji wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    res = db.get_service_info(username, service_name)
    if res != None:
        response = {}
        response['image_url'] = res[2]
        response['service_url'] = res[1]
        response['service_name'] = service_name
        response['user_name'] = res[0]
        return jsonify(response), 200
    else:
        return ERROR_MESSAGE, 400


@ app.route('/info', methods=["POST"])
def add_info():
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    ERROR_MESSAGE = "Podczas dodawania informacji wystąpił błąd, czy jesteś pewien że poprawnie wypełniłeś wszystkie pola?"
    if v.is_empty(request.form):
        return ERROR_MESSAGE, 400

    name = request.form.get("addi-name")
    user_name = request.form.get("addi-username")
    service_url = request.form.get("addi-url")
    image_url = request.form.get("addi-image")
    master_password = request.form.get("addi-master")

    if not v.is_service_name_valid(name) or not v.is_password_safe(master_password, "główne"):
        return ERROR_MESSAGE, 400

    if verify_master(username, master_password):
        if db.add_service_info(username, name, user_name, service_url, image_url):
            return "Dodano nowe informacje", 201
        else:
            return ERROR_MESSAGE, 400
    else:
        return ERROR_MESSAGE, 401


@ app.route('/genpass/<pass_length>', methods=["GET"])
def generate_pass(pass_length):
    username = session.get("username")
    if not username:
        flash("Ta akcja wymaga zalogowania!")
        return redirect('load_login', 401)

    response = {}
    if not pass_length:
        response['password'] = generate_password()
    else:
        response['password'] = generate_password(int(pass_length))
    return jsonify(response), 200


def generate_password(length=8):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password):
            break
    return password
