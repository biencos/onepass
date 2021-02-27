import os
import sys
from getpass import getpass
import re
from datetime import datetime, timedelta
from random import randint

from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
import uuid

from onepass.db.db_manager import DbManager
from onepass.models.aes import AESCipher
from onepass.models.validation import Validator
from onepass.models.user_manager import UserManager

APP_NAME = "onepass"
load_dotenv()
db = DbManager(os.getenv("DATABASE"))
v = Validator()
um = UserManager(db, v)

# Configurations
HA = "\t\t\t"       # HEADER_ACAPIT
SA = "\t\t"         # SUBHEADER_ACAPIT
TA = "\t"           # TEXT_ACAPIT


def main():
    print("")
    print(f"{HA}\t{APP_NAME}")

    ACTIONS = ['login', 'register', 'exit']
    selected = 1
    while 0 < selected < len(ACTIONS):
        print("\n")
        print_actions(ACTIONS, "-")
        print("")
        selected = get_selected_option(input(":"), 1, len(ACTIONS))
        if selected == 1:
            username = start_login()
            start_getting_passwords(username)

            LOGIN_ACTIONS = ['show passwords',
                             'add password', 'decrypt password', 'decrypt all passwords',  'exit']
            while 0 < selected < len(LOGIN_ACTIONS):
                print("\n")
                print_actions(LOGIN_ACTIONS, "-")
                print("")
                selected = get_selected_option(
                    input(":"), 1, len(LOGIN_ACTIONS))

                if selected == 1:
                    start_getting_passwords(username)
                elif selected == 2:
                    start_adding_password(username)
                elif selected == 3:
                    start_decrypting_password(username)
                elif selected == 4:
                    start_decrypting_all_passwords(username)
        elif selected == 2:
            start_register()
    print(f"{SA}See you next time")
    return


def print_actions(actions, prfx):
    print(f"{HA}WHAT DO YOU WANT TO DO?")
    print("")
    [print(f"{HA}{i+1} {prfx} {actions[i]}")
     for i in range(len(actions))]


def get_selected_option(inp, inp_limit, inp_limit1):
    if not v.is_option_valid(inp, inp_limit, inp_limit1):
        print(
            f"{TA}Option must be a number between {inp_limit} and {inp_limit1}")
        sys.exit(0)
    return int(inp)


def print_passwords(passwords, decoded=False):
    if len(passwords) > 0:
        print(
            f"{TA}Service Name\tService Url\tUsername\tPassword\t[ Password ID ]")
        for p in passwords:
            sp = p["service_password"] if decoded else "*" * 8
            print(
                f'{TA}{p["service_name"]}\t\t{p["service_url"]}\t{p["service_username"]}\t{sp}\t[ {p["password_id"]} ]')
    else:
        print(f"{HA}There is no passwords yet.")


def start_register():
    print(f"{HA}Sign Up")
    print('Enter your credentials\n')
    name = input("Username: ")
    password = getpass("Password: ")
    password1 = getpass("Repeat Password: ")
    master = getpass("Master Password: ")
    master1 = getpass("Repeat Master Password: ")
    if not um.register(name, password, password1, master, master1):
        print(f"{TA}Error! Something went wrong during registration\n")
        return
    print(f"{TA}Welcome on board, now you can login\n")


def start_login():
    print(f"{HA}Sign in")
    username, password = input("Username: "), getpass("Password: ")
    if not um.login(username, password):
        print(f"{TA}Error! Something went wrong during login")
        return
    return username


def start_getting_passwords(username):
    passwords = get_passwords(username)
    if not passwords:
        print(f"{TA}There was an error during getting passwords \n")
    else:
        print_passwords(passwords)


def get_passwords(username):
    res = db.get_user_passwords(username)
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


def start_adding_password(username):
    print(f"{HA}Add New Password")
    master_password = getpass("Master Password: ")
    if not verify_master(username, master_password):
        print("Error! Wrong Master Password")
        return

    service_name = input("Service Name: ")
    if not v.is_service_name_valid(service_name):
        print("Incorrect value of service name")
        return

    service_url = input("Service URL: ")
    if not v.is_service_url_valid(service_url):
        print("Incorrect value of service url")
        return

    service_username = input("Username used in service: ")
    if not v.is_service_username_valid(service_username):
        print("Incorrect value of service username")
        return

    service_password = getpass("Password used in service: ")
    service_password1 = getpass("Repeat Password: ")
    if not v.is_passwords_safe(service_password, service_password1, ""):
        return

    password_id = str(uuid.uuid4())[0:6]

    if not add_password(username, master_password, service_name, service_url, service_username, service_password, password_id):
        print("Error! Something went wrong while adding password")
        return
    print("New password was succesfully added!")


def add_password(username, master_password, service_name, service_url, service_username, service_password, password_id):
    encrypted = encrypt_password(service_password, master_password)
    if db.add_user_password(username, service_name, service_url, service_username, encrypted, password_id):
        return True
    return False


def verify_master(username, master_password):
    master_password = master_password.encode()
    hashed = db.get_user_master_password(username)
    if hashed != None:
        return checkpw(master_password, hashed)
    return False


def start_decrypting_password(username):
    print(f"{HA}Decrypt Password")
    master_password = getpass("Master Password: ")
    if not verify_master(username, master_password):
        print("Error! Wrong Master Password")
        return
    password_id = input("Password ID: ")
    if len(password_id) != 6:
        print("There in no password with this id!")
        return
    decrypted_password = get_password(username, master_password, password_id)
    if not decrypted_password:
        print("There in no password with this id!")
        return
    print("Your password is " + decrypted_password)


def start_decrypting_all_passwords(username):
    print(f"{HA}Decrypt All Passwords")
    master_password = getpass("Master Password: ")
    if not verify_master(username, master_password):
        print("Error! Wrong Master Password")
        return

    passwords = get_passwords(username)
    for p in passwords:
        password_id = p["password_id"]
        encrypted = get_password(username, master_password, password_id)
        p["service_password"] = encrypted
    print_passwords(passwords, True)


def get_password(username, master_password, password_id):
    password = db.get_user_service_password(username, password_id)
    if password != None:
        return decrypt_password(master_password, password)
    return None


def encrypt_password(password, master_password):
    c = AESCipher(key=master_password)
    return c.encrypt(password)


def decrypt_password(master_password, password):
    c = AESCipher(key=master_password)
    return c.decrypt(password)


if __name__ == "__main__":
    main()
