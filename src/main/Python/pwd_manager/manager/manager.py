import os
import base64
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from pwd_manager.storage.user_json_store import UserStore
from pwd_manager.cfg.pwd_manager_config import JSON_FILES_PATH

class Manager:
    """
    This class decrypts the users.json file and passes the corresponding user's information to the User class
    """

    def __init__(self):
        # ==============================================================================================================
        # ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
        # ==============================================================================================================
        # ................@@.........@@....@@.......@@@@@@....@@....@@...@@@@@@...@@....@@...@@@@@@@@...................
        # .................@@...@...@@...@@..@@.....@@   @@...@@@@..@@.....@@.....@@@@..@@...@@..@@.....................
        # ..................@@ @@@ @@...@@@@@@@@....@@@@@@....@@..@@@@.....@@.....@@..@@@@...@@....@@...................
        # ...................@@...@@...@@......@@...@@   @@...@@....@@...@@@@@@...@@....@@...@@@@@@@@...................
        # ==============================================================================================================
        # \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/
        # ==============================================================================================================
        self.__MASTER_PASSWORD = "contraseña segurísima"    # ----------------------------------------------------------
        # ==============================================================================================================
        # /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\
        # ==============================================================================================================
        # ................@@.........@@....@@.......@@@@@@....@@....@@...@@@@@@...@@....@@...@@@@@@@@...................
        # .................@@...@...@@...@@..@@.....@@   @@...@@@@..@@.....@@.....@@@@..@@...@@..@@.....................
        # ..................@@ @@@ @@...@@@@@@@@....@@@@@@....@@..@@@@.....@@.....@@..@@@@...@@....@@...................
        # ...................@@...@@...@@......@@...@@   @@...@@....@@...@@@@@@...@@....@@...@@@@@@@@...................
        # ==============================================================================================================
        # ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
        # ==============================================================================================================

        self.__users = self.auth_decrypt_users()
    def get_user_info(self, username):
        """Returns the user's information"""
        # Search the user in self.__users
        for user in self.__users:
            if user["username"] == username:
                return user
        return None

    def add_user(self, user):
        """Adds a user to self.__users"""
        if not isinstance(user, dict):
            raise ValueError("Invalid user object")
        self.__users.append(user)

    def update_user(self, user):
        """Updates a user in self.__users"""
        if not isinstance(user, dict):
            raise ValueError("Invalid user object")
        for i in range(len(self.__users)):
            if self.__users[i]["username"] == user["username"]:
                self.__users[i] = user
                return True
        return False

    def derive_password(self, salt=None):
        if salt is None:
            # generate salt
            salt = os.urandom(16)
        # derive
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        key = kdf.derive(self.__MASTER_PASSWORD.encode())  # .encode to convert str to bytes
        return salt, key

    def auth_encrypt_users(self):
        """Encrypts and stores the users.json file"""
        data = self.__users
        # Call the derive_password method to get the salt and the key
        # Each time we encrypt, we use a new salt, so the encryption key is different each time
        # The encryption key is derived from the user's password (the one introduced when the user logged in)
        salt, key = self.derive_password()
        # Create the Fernet object with the key
        f = Fernet(base64.urlsafe_b64encode(key))
        # Encrypt the data
        data = str(data)
        encrypted_data = f.encrypt(data.encode())
        # Save the salt into a json file
        with open(JSON_FILES_PATH + "master_salt.json", "w", encoding="utf-8", newline="") as file:
            json.dump(str(salt), file, indent=2)
        # Save the encrypted data into a json file
        UserStore().save(str(encrypted_data))
        return True

    def auth_decrypt_users(self):
        # Load the encrypted data from the users.json file
        data = UserStore().load()
        # If there is no data
        if data == []:
            return []
        # Load the salt from the master_salt.json file
        with open(JSON_FILES_PATH + "master_salt.json", "r", encoding="utf-8", newline="") as file:
            salt = json.load(file)
        # Obtain the key from the user's password and the encryption salt
        key = self.derive_password(eval(salt))[1]
        # Create the Fernet object with the key
        f = Fernet(base64.urlsafe_b64encode(key))
        # Decrypt the data
        try:
            decrypted_data = f.decrypt(eval(data))
        except Exception as ex:
            raise ValueError("El archivo de usuarios sufrió modificaciones de forma externa") from ex
        return eval(decrypted_data)
