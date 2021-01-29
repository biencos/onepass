import os
import re

from flask import flash
from dotenv import load_dotenv

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


# REGISTER
def is_empty(form):
    empty_fields = [f for f in form.values() if not f]
    if len(empty_fields) != 0:
        flash("Aby zarejestrować się, musisz wypełnić wszystkie pola!")
        return True
    return False


def is_username_valid(username):
    if len(username) < USERNAME_MIN_LENGTH:
        flash("Nazwa użytkownika jest zbyt krótka")
        return False
    if len(username) > USERNAME_MAX_LENGTH:
        flash("Nazwa użytkownika jest zbyt długa")
        return False
    if not re.match('^[a-z]+$', username):
        flash("Nazwa użytkownika może składać się tylko z małych liter!")
        return False
    return True


def is_email_valid(email):
    if len(email) < EMAIL_MIN_LENGTH:
        flash("Email jest zbyt krótki")
        return False
    if len(email) > EMAIL_MAX_LENGTH:
        flash(f"Email nie może być dłuższy niż {EMAIL_MAX_LENGTH} znaków")
        return False
    if not re.search('[^@]+@[^@]+\.[^@]+', email):
        flash("Niepoprawny email, popraw go i spróbuj ponownie!")
        return False
    return True


def is_password_safe(password, prfx):
    if not password:
        flash(f"Hasło {prfx} nie może być puste!")
        return False
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(
            f"Hasło {prfx} musi mieć conajmniej {PASSWORD_MIN_LENGTH} znaków!")
        return False
    if len(password) > PASSWORD_MAX_LENGTH:
        flash(f"Hasło {prfx} jest zbyt długie!")
        return False
    regex = ("^(?=.*[a-z])(?=." + "*[A-Z])(?=.*\\d)" +
             "(?=.*[-+_!@#$%^&*., ?]).+$")
    if not re.search(re.compile(regex), password):
        flash(f"Hasło {prfx} musi składać się przynajmniej: z jednej dużej litery, z jednego małego znaku, z jednej cyfry oraz z jednego znaku specjalnego!")
        return False
    return True


def is_passwords_safe(password, password1, prfx):
    if not is_password_safe(password, prfx):
        return False
    if password != password1:
        flash(f"Podane hasła {prfx} nie pasują do siebie!")
        return False
    return True


def is_user_valid(user):
    if not is_username_valid(user['username']) or not is_email_valid(user['email']):
        return False
    if not is_passwords_safe(user['password'], user['password1'], "") or not is_passwords_safe(user['master1'], user['master1'], "główne"):
        return False
    if db.is_registred(user['username']):
        flash("Niepoprawna nazwa użytkownika, popraw ją i spróbuj ponownie")
        return False
    return True


""" 
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
        hashed = get_user_password(username)
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


def get_user_password(username):
    res = select_from_db(
        'SELECT password FROM users WHERE username = ?', [username])
    return res[0]


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

    # if is_email_registered(email):
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
 """
