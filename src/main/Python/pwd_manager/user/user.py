"""
User module for the password manager.
"""

import uuid
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pwd_manager.storage.user_json_store import UserStore
from pwd_manager.storage.pwd_user_json_store import PwdStore
from pathlib import Path


def generate_uuid():
    """Generates a uuid"""
    return uuid.uuid4()


class User:
    """
    Class for providing the methods for registering a new user
    """

    def __init__(self):
        self.__username = ""
        self.__password = ""
        self.__user_id = ""
        self.__stored_passwords = []

    def login_user(self, username, password):
        """Login the user"""
        self.__username = username
        self.__password = password
        users = UserStore().load()
        for user in users:
            if user["user_name"] == self.__username:
                login = self.check_password(eval(user["salt"]), eval(user["password"]))
                if login:
                    self.__user_id = user["user_id"]
                    # Read the passwords from the user after login
                    self.__stored_passwords = PwdStore().lists(self.user_id)
                    return self.__username
                else:
                    raise ValueError("Nombre de usuario o contraseña incorrectas")
        raise ValueError("Nombre de usuario o contraseña incorrectas")

    def register_user(self, username, password):
        """Register the user into the users file"""
        self.__username = username
        self.__password = password
        self.__user_id = generate_uuid()
        self.__save_user()
        return self.__username

    # Method to generate uuid

    def save_user(self):
        """Save the user into the user's JSON file"""
        # Check if the user is already registered
        user = UserStore().find_item(self.__username, "user_name")
        if user is not None:
            raise ValueError("Nombre de usuario ya en uso")

        salt_password = self.derive_password()
        user_dict = {
            "user_name": self.__username,
            "password": str(salt_password[1]),
            "salt": str(salt_password[0]),
            "user_id": str(self.__user_id)
        }
        UserStore().add_item(user_dict)

    def derive_password(self):
        salt = os.urandom(16)
        # derive
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        key = kdf.derive(self.__password.encode())  # .encode to convert str to bytes
        return salt, key

    def check_password(self, salt, key):
        # verify
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        try:
            kdf.verify(self.__password.encode(), key)
            return True
        except:
            return False


    def add_password(self, web, web_password, web_note):
        pwd_dict = {
            "web": web,
            "web_password": web_password,
            "web_note": web_note,
        }
        # Append the password dictionary to the user's passwords list
        self.__stored_passwords.append(pwd_dict)

    def delete_password(self):
        pass


    @property
    def username(self):
        """gets the user_name value"""
        return self.__username

    @username.setter
    def username(self, value):
        self.__username = value

    @property
    def password(self):
        """gets the password value"""
        return self.__password

    @password.setter
    def password(self, value):
        self.__password = value

    @property
    def user_id(self):
        """gets the user_id value"""
        return self.__user_id

    @user_id.setter
    def user_id(self, value):
        self.__user_id = value

    @property
    def stored_passwords(self):
        """gets the stored_passwords value"""
        return self.__stored_passwords

    @stored_passwords.setter
    def stored_passwords(self, value):
        self.__stored_passwords = value

    def __del__(self):
        # Before deleting the user, save the passwords
        PwdStore().save(self.__stored_passwords, self.__user_id)
