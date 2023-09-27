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
        user = User(user_name, password)
        user.save_user()
        return user.user_name
