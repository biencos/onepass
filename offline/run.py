import os
from getpass import getpass

from dotenv import load_dotenv
import uuid

from src.db.db_manager import DbManager
from src.models.validation import Validator
from src.models.user_manager import UserManager
from src.models.passwords_manager import PasswordsManager


APP_NAME = "onepass"
HA = "\t\t\t"           # HEADER_ACAPIT
SA = "\t\t"             # SUBHEADER_ACAPIT
TA = "\t"               # TEXT_ACAPIT

load_dotenv()
db, v = DbManager(os.getenv("DATABASE")), Validator()
um, pm = UserManager(db, v), PasswordsManager(db, v)


def main():
    print("")
    print(f"{HA}\t{APP_NAME}")

    ACTIONS = ['login', 'register', 'exit']
    selected = 1
    while 0 <= selected < len(ACTIONS):
        print("\n")
        print_actions(ACTIONS, "-")
        print("")
        selected = get_selected_option(input(":"), 1, len(ACTIONS))

        if selected == 0:
            print(f"{TA}Incorrect value of option")
        elif selected == 1:
            username = start_login()
            start_getting_passwords(username)

            LOGIN_ACTIONS = ['show passwords', 'add password', 'decrypt password',
                             'decrypt all passwords', 'generate random password', 'exit']
            while 0 < selected < len(LOGIN_ACTIONS):
                print("\n")
                print_actions(LOGIN_ACTIONS, "-")
                print("")
                selected = get_selected_option(
                    input(":"), 1, len(LOGIN_ACTIONS))

                if selected == 0:
                    print(f"{TA}Incorrect value of option")
                elif selected == 1:
                    start_getting_passwords(username)
                elif selected == 2:
                    start_adding_password(username)
                elif selected == 3:
                    start_decrypting_password(username)
                elif selected == 4:
                    start_decrypting_all_passwords(username)
                elif selected == 5:
                    start_generating_random_password()
        elif selected == 2:
            start_register()
    print(f"{SA}See you next time")
    return


def print_actions(actions, prfx):
    print(f"{HA}WHAT DO YOU WANT TO DO?")
    print("")
    [print(f"{HA}{i+1} {prfx} {actions[i]}") for i in range(len(actions))]


def get_selected_option(inp, inp_limit, inp_limit1):
    if not v.is_option_valid(inp, inp_limit, inp_limit1):
        return 0
    return int(inp)


def start_register():
    print(f"{HA}Sign Up")
    name = input("Username: ")
    password = getpass("Password: ")
    password1 = getpass("Repeat Password: ")
    master = getpass("Master Password: ")
    master1 = getpass("Repeat Master Password: ")
    if not um.register(name, password, password1, master, master1):
        print(f"\n{TA}Error! Something went wrong during registration\n")
        return
    print(f"\n{TA}Welcome on board, now you can login\n")


def start_login():
    print(f"{HA}Sign in")
    username, password = input("Username: "), getpass("Password: ")
    if not um.login(username, password):
        print(f"\n{TA}Error! Something went wrong during login\n")
        return
    return username


def start_getting_passwords(username):
    passwords = pm.get_passwords(username)
    if not passwords:
        print(f"\n{TA}There was an error during getting passwords\n")
    else:
        print_passwords(passwords)


def start_adding_password(username):
    print(f"{HA}Add New Password")
    master_password = getpass("Master Password: ")
    if not um.verify_master(username, master_password):
        print(f"\n{TA}Error! Wrong Master Password\n")
        return
    service_name = input("Service Name: ")
    if not v.is_service_name_valid(service_name):
        print(f"\n{TA}Incorrect value of service name\n")
        return
    service_url = input("Service URL: ")
    if not v.is_service_url_valid(service_url):
        print(f"\n{TA}Incorrect value of service url\n")
        return
    service_username = input("Username used in service: ")
    if not v.is_service_username_valid(service_username):
        print(f"\n{TA}Incorrect value of service username\n")
        return
    service_password = getpass("Password used in service: ")
    service_password1 = getpass("Repeat Password: ")
    if not v.is_passwords_safe(service_password, service_password1, ""):
        return
    password_id = str(uuid.uuid4())[0:6]
    if not pm.add_password(username, master_password, service_name, service_url, service_username, service_password, password_id):
        print(f"\n{TA}Error! Something went wrong while adding password\n")
        return
    print(f"\n{TA}New password was succesfully added!\n")


def start_decrypting_password(username):
    print(f"{HA}Decrypt Password")
    master_password = getpass("Master Password: ")
    if not um.verify_master(username, master_password):
        print(f"\n{TA}Error! Wrong Master Password\n")
        return
    password_id = input("Password ID: ")
    if len(password_id) != 6:
        print(f"\n{TA}There in no password with this id!\n")
        return
    decrypted_password = pm.get_password(
        username, master_password, password_id)
    if not decrypted_password:
        print(f"\n{TA}There in no password with this id!\n")
        return
    print(f"\n{TA}Your password is: " + decrypted_password + "\n")


def start_decrypting_all_passwords(username):
    print(f"{HA}Decrypt All Passwords")
    master_password = getpass("Master Password: ")
    if not um.verify_master(username, master_password):
        print(f"\n{TA}Error! Wrong Master Password\n")
        return
    passwords = pm.get_passwords(username)
    for p in passwords:
        password_id = p["password_id"]
        encrypted = pm.get_password(username, master_password, password_id)
        p["service_password"] = encrypted
    print_passwords(passwords, True)


def start_generating_random_password():
    print(f"{HA}Generate Random Password\n")
    password_length = input("Password Length (>=8): ")
    if not v.is_password_length_valid(password_length):
        print(f"{TA}Password must be at least 8 characters long")
        return
    password_length = int(password_length)
    password = pm.generate_password(password_length)
    print(f"{TA}Your password is ready:\n")
    print(f"{HA}{password}\n")


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


if __name__ == "__main__":
    main()
