import os

from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw


load_dotenv()
SALT_LENGTH = int(os.getenv("SALT_LENGTH"))


class UserManager:
    def __init__(self, db_manager, validation_manager):
        self.db = db_manager
        self.v = validation_manager

    def register(self, name, password, password1, master, master1):
        user = {'username': name, 'password': password,
                'password1': password1, 'master': master, 'master1': master1}
        if not self.v.is_user_valid(user):
            return False
        hashed = self.hash_pass(user['password'])
        master_hashed = self.hash_pass(user['master'])
        if self.db.register_user(user['username'], hashed, master_hashed):
            return True
        return False

    def hash_pass(self, password, salt_length=SALT_LENGTH):
        password, salt = password.encode(),  gensalt(salt_length)
        return hashpw(password, salt)

    def login(self, username, password):
        if not self.v.is_username_login_valid(username) or not self.v.is_password_login_valid(password):
            return False
        if self.db.is_registred(username):
            hashed = self.db.get_user_password(username)
            if hashed:
                if checkpw(password.encode(), hashed):
                    return True
        return False

    def verify_master(self, username, master_password):
        master_password = master_password.encode()
        hashed = self.db.get_user_master_password(username)
        if hashed != None:
            return checkpw(master_password, hashed)
        return False
