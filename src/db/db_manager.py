from .db import Db


class DbManager:
    def __init__(self, DB_PATH):
        self.db = Db(DB_PATH)

    def is_registred(self, username):
        return self.db.select_from_db('SELECT id FROM users WHERE username = ?', [username]) != None

    def get_user_password(self, username):
        return self.db.select_from_db('SELECT password FROM users WHERE username = ?', [username])[0]

    def get_user_master_password(self, username):
        return self.db.select_from_db('SELECT master_password FROM users WHERE username = ?', [username])[0]

    def register_user(self, username, hashed, master_hashed):
        return self.db.query_db('INSERT INTO users (username, password, master_password) VALUES (?, ?, ?)', [username, hashed, master_hashed])

    def get_user_passwords(self, username):
        return self.db.select_from_db('SELECT service_name, service_url, service_username, service_password, password_id FROM passwords WHERE username = ?', [username], "all")

    def add_user_password(self, username, service_name, service_url, service_username, encrypted, password_id):
        query = 'INSERT INTO passwords (username, service_name, service_url, service_username, service_password, password_id) VALUES (?, ?, ?, ?, ?, ?)'
        values = [username, service_name, service_url,
                  service_username, encrypted, password_id]
        return self.db.query_db(query, values)

    def get_user_service_password(self, username, password_id):
        return self.db.select_from_db('SELECT service_password FROM passwords WHERE username = ? AND password_id = ?', [username, password_id])[0]
