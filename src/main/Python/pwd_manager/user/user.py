"""
User module for the password manager.
"""

import uuid
import json
from pathlib import Path

JSON_FILES_PATH = str(Path.home()) + "/Desktop/python_projects/criptografia_proyecto/src/data/"

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
        try:
            with open(JSON_FILES_PATH + 'users.json', 'r') as file:
                users = json.load(file)
        except FileNotFoundError:
            users = [
                {
                    "user_name": self.user_name,
                    "password": self.password,
                    "user_id": str(self.user_id)
                }
            ]
        else:
            users.append({
                "user_name": self.user_name,
                "password": self.password,
                "user_id": str(self.user_id)
            })

        # Write the users.json file
        with open(JSON_FILES_PATH + 'users.json', 'w') as file:
            json.dump(users, file, indent=2)

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
