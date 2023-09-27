"""
User module for the password manager.
"""

import uuid
import json
from pathlib import Path

JSON_FILES_PATH = str(Path.home()) + "/PycharmProjects/criptografia_proyecto/src/data/"
#Carrero PATH /PycharmProjects/criptografia_proyecto/src/data/
#Dario PATH /Desktop/python_projects/criptografia_proyecto/src/data/


class User():
    """
    Class for providing the methods for registering a new user
    """

    def __init__(self, user_name, password):
        self.__user_name = user_name
        self.__password = password
        self.__user_id = self.generate_uuid()


    # Method to generate uuid
    def generate_uuid(self):
        """Generates a uuid"""
        return uuid.uuid4()

    def save_user(self):
        """Save the user into the user's JSON file"""
        # Read the users.json file
        users = self.get_users()
        if users == []:
            users.append({
                    "user_name": self.user_name,
                    "password": self.password,
                    "user_id": str(self.user_id)
                })
        else:
            # Check that the user is not already registered
            for user in users:
                if user["user_name"] == self.user_name:
                    raise ValueError("Username already taken")

            # Add the new user to the users list
            users.append({
                "user_name": self.user_name,
                "password": self.password,
                "user_id": str(self.user_id)
            })

        # Write the users.json file
        with open(JSON_FILES_PATH + 'users.json', 'w') as file:
            json.dump(users, file, indent=2)

    def check_user(self):
        """Checks if the user is registered with the given password"""
        # Read the users.json file
        users = self.get_users()
        for user in users:
            if user["user_name"] == self.user_name and user["password"] == self.password:
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

    def añadir(self):
        pass

    def eliminar(self):
        pass

    @property
    def user_name(self):
        """gets the user_name value"""
        return self.__user_name

    @user_name.setter
    def user_name(self, value):
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
