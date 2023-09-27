"""
Login module for the password manager.
"""

from pwd_manager.user.user import User

class Login():
    """
    Class for providing the methods for registering a new user
    """
    def __init__(self):
        pass

    def login_user(self, user_name, password):
        """Login the user"""
        user = User(user_name, password)
        login = user.check_user()
        if login:
            print("Login successful")
            return user.user_id
        else:
            print("Login failed")
            return None
