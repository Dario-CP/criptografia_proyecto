"""
User module for the password manager.
"""

import uuid
import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pathlib import Path

JSON_FILES_PATH = str(Path.home()) + "/PycharmProjects/criptografia_proyecto/src/data/"
#Carrero PATH /PycharmProjects/criptografia_proyecto/src/data/
#Dario PATH /Desktop/python_projects/criptografia_proyecto/src/data/


class User():
    """
    Class for providing the methods for registering a new user
    """

    def __init__(self):
        self.username = ""
        self.password = ""
        self.user_id = self.generate_uuid()

    def login_user(self, username, password):
        """Login the user"""
        self.username = username
        self.password = password
        login = self.check_user()
        if login:
            print("Login successful")
            return self.username
        else:
            print("Login failed")
            return None

    def register_user(self, username, password):
        """Register the user into the users file"""
        self.username = username
        self.password = password
        self.save_user()
        return self.username

    # Method to generate uuid
    def generate_uuid(self):
        """Generates a uuid"""
        return uuid.uuid4()

    def save_user(self):
        """Save the user into the user's JSON file"""
        # Read the users.json file
        users = self.get_users()
        salt_password = self.derive_password()
        if users == []:
            users.append({
                "user_name": self.username,
                "password": str(salt_password[1]),
                "salt": str(salt_password[0]),
                "user_id": str(self.user_id)
                })
        else:
            # Check that the user is not already registered
            for user in users:
                if user["user_name"] == self.username:
                    raise ValueError("Username already taken")

            # Add the new user to the users list
            users.append({
                "user_name": self.username,
                "password": str(salt_password[1]),
                "salt": str(salt_password[0]),
                "user_id": str(self.user_id)
            })

        # Write the users.json file
        with open(JSON_FILES_PATH + 'users.json', 'w', encoding='utf-8') as file:
            json.dump(users, file, indent=2)

    def check_user(self):
        """Checks if the user is registered with the given password"""
        # Read the users.json file
        users = self.get_users()
        for user in users:
            if user["user_name"] == self.username and self.check_password(eval(user["salt"]), eval(user["password"])):
                return True
        return False


    def get_users(self):
        """Returns a list of all the users"""
        # Read the users.json file
        try:
            with open(JSON_FILES_PATH + 'users.json', 'r') as file:
                users = json.load(file)
        except FileNotFoundError:
            users = []
        return users

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
        key = kdf.derive(self.password.encode())    # .encode to convert str to bytes
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
            kdf.verify(self.password.encode(), key)
            return True
        except:
            return False

    def __del__(self):
        pass
        # print("User logged out")

    def añadir(self):
        pass

    def eliminar(self):
        pass

    @property
    def username(self):
        """gets the user_name value"""
        return self.__user_name

    @username.setter
    def username(self, value):
        self.__user_name = value

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
