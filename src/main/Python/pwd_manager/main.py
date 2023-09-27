"""
Main file for the password manager.
"""

from pwd_manager.register.register import Register

def main():
    user = input("Enter your user name: ")
    password = input("Enter your password: ")
    Register().register_user(user, password)

if __name__ == "__main__":
    main()