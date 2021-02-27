import os
import re

from dotenv import load_dotenv

from ..db.db_manager import DbManager


load_dotenv()
USERNAME_MIN_LENGTH = int(os.getenv("USERNAME_MIN_LENGTH"))
USERNAME_MAX_LENGTH = int(os.getenv("USERNAME_MAX_LENGTH"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH"))
PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH"))
SERVICE_NAME_MIN_LENGTH = int(os.getenv("SERVICE_NAME_MIN_LENGTH"))
SERVICE_NAME_MAX_LENGTH = int(os.getenv("SERVICE_NAME_MAX_LENGTH"))
SERVICE_URL_MIN_LENGTH = int(os.getenv("SERVICE_URL_MIN_LENGTH"))
SERVICE_URL_MAX_LENGTH = int(os.getenv("SERVICE_URL_MAX_LENGTH"))
SERVICE_USERNAME_MIN_LENGTH = int(os.getenv("SERVICE_USERNAME_MIN_LENGTH"))
SERVICE_USERNAME_MAX_LENGTH = int(os.getenv("SERVICE_USERNAME_MAX_LENGTH"))
db = DbManager(os.getenv("DATABASE"))


class Validator:
    def is_username_valid(self, username):
        if len(username) < USERNAME_MIN_LENGTH:
            print("Username is too short")
            return False
        if len(username) > USERNAME_MAX_LENGTH:
            print("Username is too long")
            return False
        if not re.match('^[a-z]+$', username):
            print("Username can only contain lowercase letters")
            return False
        return True

    def is_password_safe(self, password, prfx):
        if not password:
            print(f"{prfx} Password can't be empty!")
            return False
        if len(password) < PASSWORD_MIN_LENGTH:
            print(
                f"{prfx} Password is too short!")
            return False
        if len(password) > PASSWORD_MAX_LENGTH:
            print(f"{prfx} Password is too long!")
            return False
        regex = ("^(?=.*[a-z])(?=." + "*[A-Z])(?=.*\\d)" +
                 "(?=.*[-+_!@#$%^&*., ?]).+$")
        if not re.search(re.compile(regex), password):
            print(
                f"{prfx} Password must have at least one: lowercase letter, uppercase letter, digit, special character!")
            return False
        return True

    def is_passwords_safe(self, password, password1, prfx):
        if not self.is_password_safe(password, prfx):
            return False
        if password != password1:
            print(f"{prfx} Passwords do not match!")
            return False
        return True

    def is_user_valid(self, user):
        if not self.is_username_valid(user['username']):
            return False
        if not self.is_passwords_safe(user['password'], user['password1'], "") or not self.is_passwords_safe(user['master'], user['master1'], "Master"):
            return False
        if db.is_registred(user['username']):
            print("\nIncorrect value of username\n")
            return False
        return True

    def is_username_login_valid(self, username):
        if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH:
            return False
        return True

    def is_password_login_valid(self, password):
        if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
            return False
        return True

    def is_service_name_valid(self, name):
        if len(name) < SERVICE_NAME_MIN_LENGTH or len(name) > SERVICE_NAME_MAX_LENGTH:
            return False
        return True

    def is_service_url_valid(self, url):
        if len(url) < SERVICE_NAME_MIN_LENGTH or len(url) > SERVICE_NAME_MAX_LENGTH:
            return False
        return True

    def is_service_username_valid(self, service_username):
        if len(service_username) < SERVICE_USERNAME_MIN_LENGTH or len(service_username) > SERVICE_USERNAME_MAX_LENGTH:
            return False
        return True

    def is_option_valid(self, inp, inp_limit, inp_limit1):
        try:
            inp = int(inp)
        except:
            return False
        if inp < inp_limit or inp > inp_limit1:
            return False
        return True

    def is_password_length_valid(self, length, length_limit=8):
        try:
            length = int(length)
            if length < length_limit:
                return False
        except:
            return False
        return True
