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
DB_PATH = os.getenv("DATABASE")
db = DbManager(DB_PATH)


class Validator:
    def is_option_valid(self, inp, inp_limit, inp_limit1):
        try:
            inp = int(inp)
        except:
            return False
        if inp < inp_limit or inp > inp_limit1:
            return False
        return True

    # REGISTER

    def is_username_valid(self, username):
        if len(username) < USERNAME_MIN_LENGTH:
            print("Nazwa użytkownika jest zbyt krótka")
            return False
        if len(username) > USERNAME_MAX_LENGTH:
            print("Nazwa użytkownika jest zbyt długa")
            return False
        if not re.match('^[a-z]+$', username):
            print("Nazwa użytkownika może składać się tylko z małych liter!")
            return False
        return True

    def is_password_safe(self, password, prfx):
        if not password:
            print(f"Hasło {prfx} nie może być puste!")
            return False
        if len(password) < PASSWORD_MIN_LENGTH:
            print(
                f"Hasło {prfx} musi mieć conajmniej {PASSWORD_MIN_LENGTH} znaków!")
            return False
        if len(password) > PASSWORD_MAX_LENGTH:
            print(f"Hasło {prfx} jest zbyt długie!")
            return False
        regex = ("^(?=.*[a-z])(?=." + "*[A-Z])(?=.*\\d)" +
                 "(?=.*[-+_!@#$%^&*., ?]).+$")
        if not re.search(re.compile(regex), password):
            print(f"Hasło {prfx} musi składać się przynajmniej: z jednej dużej litery, z jednego małego znaku, z jednej cyfry oraz z jednego znaku specjalnego!")
            return False
        return True

    def is_passwords_safe(self, password, password1, prfx):
        if not self.is_password_safe(password, prfx):
            return False
        if password != password1:
            print(f"Podane hasła {prfx} nie pasują do siebie!")
            return False
        return True

    def is_user_valid(self, user):
        if not self.is_username_valid(user['username']):
            return False
        if not self.is_passwords_safe(user['password'], user['password1'], "") or not self.is_passwords_safe(user['master'], user['master1'], "główne"):
            return False
        if db.is_registred(user['username']):
            print("Niepoprawna nazwa użytkownika, popraw ją i spróbuj ponownie")
            return False
        return True

    # LOGIN

    def is_username_login_valid(self, username):
        if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH:
            return False
        return True

    def is_password_login_valid(self, password):
        if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
            return False
        return True

    # ADD PASSWORD
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
