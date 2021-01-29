from db_init import query_db, select_from_db


# REGISTER
def is_registred(username):
    res = select_from_db('SELECT id FROM users WHERE username = ?', [username])
    return res != None


def register_user(username, email, hashed, master_hashed):
    return query_db('INSERT INTO users (username, email, password, master_password) VALUES (?, ?, ?, ?)', [username, email, hashed, master_hashed])


""" # LOGIN
def save_attempt(username):
    return query_db('INSERT INTO attempts (username, ip_address, time) VALUES (?, ?, ?);', [username, get_remote_address(), datetime.now()])


def get_user_password(username):
    res = select_from_db(
        'SELECT password FROM users WHERE username = ?', [username])
    return res[0]


# RESET
def is_email_registered(email):
    res = select_from_db(
        "SELECT id FROM users WHERE email = ?", [email])
    return res != None


def is_resetting(email):
    res = select_from_db(
        "SELECT id FROM resets WHERE email = ?", [email])
    print(res)
    return res != None


def save_reset_request(email, reset_id, experience_date):
    return query_db('INSERT INTO resets (email, reset_id, end_time) VALUES (?, ?, ?);', [email, reset_id, experience_date]) """
