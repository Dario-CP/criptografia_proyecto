"""
Main file for the password manager.
"""

from pwd_manager.register.register import Register
from pwd_manager.login.login import Login


def main():
    # Select from Login or register
    input("Welcome to the password manager. Press enter to continue")
    print("Select an option:")
    print("1. Login")
    print("2. Register")
    option = ""

    while option not in ["1", "2"]:
        option = input("Select an option: ")
        if option == "1":
            # If login
            user = input("Enter your user name: ")
            password = input("Enter your password: ")
            Login().login_user(user, password)
        elif option == "2":
            # If register
            user = input("Enter your user name: ")
            password = input("Enter your password: ")
            Register().register_user(user, password)
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()