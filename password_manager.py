from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import base64
import hashlib


def load_key():
    with open("key.key", "rb") as file:
        key = file.read()
    return key


def get_fernet(master_pwd):
    salt = load_key()
    key = hashlib.pbkdf2_hmac("sha256", salt, master_pwd.encode(), 100000)[:32]
    return Fernet(base64.urlsafe_b64encode(key))


def view(master_pwd):
    fer = get_fernet(master_pwd)
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            try:
                decrypted_passw = fer.decrypt(passw.encode()).decode()
                print("User: ", user, "| Password: ", decrypted_passw)
            except:
                print("User: ", user, "| Password: Hidden (Incorrect master password)")


def add(master_pwd):
    name = input("Account Name: ")
    pwd = input("Password: ")

    fer = get_fernet(master_pwd)
    with open("passwords.txt", "a") as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")


while True:
    master_pwd = input("What is the master password? ")

    mode = input(
        "Would you like to add a new password or view existing ones (view, add), press q to quit? "
    )

    if mode == "q":
        break

    if mode == "view":
        view(master_pwd)
    elif mode == "add":
        add(master_pwd)
    else:
        print("Invalid mode.")
        continue
