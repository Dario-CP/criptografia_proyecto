"""
Register module for the Password Manager
"""

from pwd_manager.user.user import User

class Register():
    """
    Class for providing the methods for registering a new user
    """
    def __init__(self):
        pass

    def register_user(self, user_name, password):
        """Register the user into the users file"""
        my_user = User(user_name, password)
        my_user.save_user()
        return my_user.user_id
