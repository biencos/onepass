from .aes import AESCipher


class PasswordsManager:
    def __init__(self, db_manager, validation_manager):
        self.db = db_manager
        self.v = validation_manager

    def add_password(self, username, master_password, service_name, service_url, service_username, service_password, password_id):
        encrypted = self.encrypt_password(service_password, master_password)
        if self.db.add_user_password(username, service_name, service_url, service_username, encrypted, password_id):
            return True
        return False

    def get_password(self, username, master_password, password_id):
        password = self.db.get_user_service_password(username, password_id)
        if password != None:
            return self.decrypt_password(master_password, password)
        return None

    def get_passwords(self, username):
        res = self.db.get_user_passwords(username)
        if res != None:
            passes = []
            for r in res:
                p = {}
                p['service_name'] = r[0]
                p['service_url'] = r[1]
                p['service_username'] = r[2]
                p['service_password'] = r[3]
                p['password_id'] = r[4]
                passes.append(p)
            return passes
        return None

    def encrypt_password(self, password, master_password):
        c = AESCipher(key=master_password)
        return c.encrypt(password)

    def decrypt_password(self, master_password, password):
        c = AESCipher(key=master_password)
        return c.decrypt(password)
