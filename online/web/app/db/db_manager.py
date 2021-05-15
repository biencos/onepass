from datetime import datetime

from .db import query_db, select_from_db


class DbManager:
    # REGISTER
    def is_registred(self, username):
        res = select_from_db(
            'SELECT id FROM users WHERE username = ?', [username])
        return res != None

    def register_user(self, username, email, hashed, master_hashed):
        return query_db('INSERT INTO users (username, email, password, master_password) VALUES (?, ?, ?, ?)', [username, email, hashed, master_hashed])

    # LOGIN

    def get_user_password(self, username):
        res = select_from_db(
            'SELECT password FROM users WHERE username = ?', [username])
        return res[0]

    def save_attempt(self, username, ip_address, date):
        return query_db('INSERT INTO attempts (username, ip_address, time) VALUES (?, ?, ?);', [username, ip_address, date])

    # RESET

    def is_email_registered(self, email):
        res = select_from_db(
            "SELECT id FROM users WHERE email = ?", [email])
        return res != None

    def is_resetting_already(self, email):
        res = select_from_db(
            "SELECT id FROM resets WHERE email = ?", [email])
        print(res)
        return res != None

    def save_reset_request(self, email, reset_id, experience_date):
        return query_db('INSERT INTO resets (email, reset_id, end_time) VALUES (?, ?, ?);', [email, reset_id, experience_date])

    # USER CHANGES PASSWORD

    def is_allowed_for_resetting(self, reset_id):
        res = select_from_db(
            "SELECT id FROM resets WHERE reset_id = ?", [reset_id])
        return res != None

    def is_reset_link_valid(self, reset_id):
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

    def delete_reset_link(self, reset_id):
        return query_db('DELETE FROM resets WHERE reset_id = ?', [reset_id])

    def get_email_with_reset_id(self, reset_id):
        return select_from_db("SELECT email FROM resets WHERE reset_id = ?", [reset_id])

    def change_user_password(self, email, hashed):
        return query_db('UPDATE users SET password = ? WHERE email = ?', [hashed, email])

    # LOAD PASSWORDS
    def get_user_passwords(self, username):
        return select_from_db('SELECT name FROM passwords WHERE username = ?', [username], "all")

    # ADD PASSWORD
    def add_user_password(self, username, service_name, password):
        return query_db('INSERT INTO passwords (username, name, password) VALUES (?, ?, ?)', [username, service_name, password])

    def get_user_master_password(self, username):
        return select_from_db('SELECT master_password FROM users WHERE username = ?', [username])

    # GET PASS
    def get_user_pass(self, username, service_name):
        return select_from_db('SELECT password FROM passwords WHERE username = ? AND name = ?', [username, service_name])

    def change_user_pass(self, username, service_name, hashed):
        return query_db('UPDATE passwords SET password = ? WHERE username = ? AND name = ? ', [hashed, username, service_name])

    # PASSWORD HISTORY
    def insert_password_to_history(self, username, service_name, password, time):
        return query_db('INSERT INTO passwords_history (username, service_name, password, time) VALUES (?, ?, ?, ?)', [username, service_name, password, time])

    def get_password_history(self, username, service_name):
        return select_from_db('SELECT password,time FROM passwords_history WHERE username = ? AND service_name = ?', [username, service_name], "all")

    # SERVICES INFO

    def add_service_info(self, username, service_name, user_name, service_url, image_url):
        return query_db('INSERT INTO services_info (username, service_name, user_name, service_url, image_url) VALUES (?, ?, ?, ?, ?)', [username, service_name, user_name, service_url, image_url])

    def get_service_info(self, username, service_name):
        return select_from_db('SELECT user_name, service_url, image_url FROM services_info WHERE username = ? AND service_name = ?', [username, service_name])
