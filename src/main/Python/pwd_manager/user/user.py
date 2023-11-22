"""
User module for the password manager.
"""

import uuid
import os
import base64
import datetime
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
from pwd_manager.storage.pwd_user_json_store import PwdStore
from pwd_manager.manager.manager import Manager
from pwd_manager.attributes.attribute_password import Password
from pwd_manager.cfg.pwd_manager_config import DOWNLOADS_PATH
from pwd_manager.cfg.pwd_manager_config import PKI_PATH

# TODO: Quitar el atributo __pk_password y el parámetro pk_password de los métodos, así como el salt y demás

class User:
    """
    Class for providing the methods for registering a new user
    """

    def __init__(self):
        self.__username = ""
        self.__password = ""
        self.__user_id = ""
        self.__encryption_salt = ""
        self.__stored_passwords = []
        self.__manager = Manager()
        self.__serial_private_key = None   # Serialized private key

    def login_user(self, username, password, pk_password):
        """Login the user"""
        user = self.__manager.get_user_info(username)
        if user is None:
            raise ValueError("Nombre de usuario o contraseña incorrectas")

        self.__username = username
        self.__password = password
        self.__pk_password = pk_password

        login = self.check_password(self.__password, eval(user["salt"]), eval(user["password"]))
        login_pk = self.check_password(self.__pk_password, eval(user["pk_salt"]), eval(user["pk_password"]))
        if login and login_pk:
            self.__user_id = user["user_id"]
            self.__private_key = serialization.load_pem_private_key(
                eval(user["private_key"]),
                password=self.__pk_password.encode()
            )
            # Read the passwords from the user after login
            # We decrypt the passwords with Fernet using the user's password as key
            encrypted_passwords = PwdStore().lists(self.user_id)
            if encrypted_passwords != []:
                self.__stored_passwords = eval(self.auth_decrypt(eval(encrypted_passwords),
                                                                 eval(user["encryption_salt"])))
            return self.__username
        elif not login:
            raise ValueError("Nombre de usuario o contraseña incorrectas")
        elif not login_pk:
            raise ValueError("Contraseña de clave privada incorrecta")
        else:
            raise ValueError("Error inesperado")

    def register_user(self, username, password):
        """Register the user into the users file"""
        # Check if the username is empty
        if username == "":
            raise ValueError("El nombre de usuario no puede estar vacío")
        # # Check if the password of the password manager and the password for private key are the same
        # if password == pk_password:
        #     raise ValueError("Las contraseñas no pueden ser iguales por motivos de seguridad")
        # Check if the password meets the requirements
        Password(password).value
        # Password(pk_password).value
        # Remember that we store the information on user's logout
        user = self.__manager.get_user_info(username)
        if user is not None:
            raise ValueError("Nombre de usuario ya en uso")

        self.__username = username
        self.__password = password
        self.__user_id = uuid.uuid4()
        # self.__pk_password = pk_password
        return self.__username

    def save_user(self):
        """Save the user into the user's JSON file"""
        # Check if the user is already registered
        user = self.__manager.get_user_info(self.__username)
        # We always generate a new salt and key (derived password)
        salt_password = self.derive_password(self.__password)
        pk_salt_password = self.derive_password(self.__pk_password)
        serial_private_key = self.__private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                              encryption_algorithm=serialization.BestAvailableEncryption(self.__pk_password.encode()))
        serial_private_key.splitlines()[0]
        user_dict = {
            "username": self.__username,
            "password": str(salt_password[1]),
            "salt": str(salt_password[0]),
            "encryption_salt": str(self.__encryption_salt),
            "user_id": str(self.__user_id),
            "pk_password": str(pk_salt_password[1]),
            "pk_salt": str(pk_salt_password[0]),        # Private key salt
            "private_key": str(serial_private_key)      # Derived private key
        }
        # If the user is not registered, add the user to the users file
        if user is None:
            self.__manager.add_user(user_dict)
        # If the user is already registered (when the user logged in), update the user's data
        # to rotate the salt and the key
        else:
            self.__manager.update_user(user_dict)

    def derive_password(self, pwd, salt=None):
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
        key = kdf.derive(pwd.encode())  # .encode to convert str to bytes
        return salt, key

    def check_password(self,pwd,salt, key):
        # verify
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        try:
            kdf.verify(pwd.encode(), key)
            return True
        except:
            return False

    def auth_encrypt(self, data):
        # Call the derive_password method to get the salt and the key
        # Each time we encrypt, we use a new salt, so the encryption key is different each time
        # The encryption key is derived from the user's password (the one introduced when the user logged in)
        salt, key = self.derive_password(self.__password)
        # Create the Fernet object with the key
        f = Fernet(base64.urlsafe_b64encode(key))
        # Encrypt the data
        data = str(data)
        encrypted_data = f.encrypt(data.encode())
        # Return the encrypted data and the salt
        return encrypted_data, salt

    def auth_decrypt(self, data, salt):
        # Obtain the key from the user's password and the encryption salt
        key = self.derive_password(self.__password,salt)[1]
        # Create the Fernet object with the key
        f = Fernet(base64.urlsafe_b64encode(key))
        # Decrypt the data
        try:
            decrypted_data = f.decrypt(data)
        except Exception as ex:
            raise ValueError("El archivo de contraseñas del usuario sufrió modificaciones de forma externa") from ex
        # Return the decrypted data
        return decrypted_data

    def add_password(self, web, web_password, web_note):
        # Check if the web is empty
        if web == "":
            raise ValueError("El sitio de contraseña no puede estar vacío")
        # Check if the web_password is empty
        if web_password == "":
            raise ValueError("La contraseña no puede estar vacía")
        # Check if the web is already stored
        for pwd in self.__stored_passwords:
            if pwd["web"] == web:
                raise ValueError("Este sitio de contraseña ya está almacenado."
                                 "\nPara añadir otra contraseña para el mismo sitio,"
                                 "\nutilize un nombre identificativo diferente")
        # Create the password dictionary
        pwd_dict = {
            "web": web,
            "web_password": web_password,
            "web_note": web_note
        }
        # Append the password dictionary to the user's passwords list
        self.__stored_passwords.append(pwd_dict)

    def delete_password(self, web):
        # Find the password to delete
        for pwd in self.__stored_passwords:
            if pwd["web"] == web:
                # Delete the password
                self.__stored_passwords.remove(pwd)
                return True
        raise ValueError("Sitio de contraseña no encontrado")

    def download_receipt(self, pk_password):
        """
        Creates a document with a listing of the user's sites
        :return:
        """

        # Check if the password of the password manager and the password for private key are the same
        if self.__password == pk_password:
            raise ValueError("Las contraseñas no pueden ser iguales por motivos de seguridad")
        # Check if the password meets the requirements
        Password(pk_password).value

        # Check if the user already has a private key and a certificate
        if self.__serial_private_key is None:
            # If the user doesn't have a certificate, generate a new one
            self.generate_certificate(pk_password)

        now = datetime.datetime.now()
        receipt_filename = (DOWNLOADS_PATH + "recibo_" + str(self.__username) + "_" +
                            now.strftime("%d-%m-%Y_%H-%M-%S"))
        signature_filename = (DOWNLOADS_PATH + "firma_" + str(self.__username) + "_" +
                              now.strftime("%d-%m-%Y_%H-%M-%S"))

        # Create the document
        with open(receipt_filename + ".txt", "w", encoding="utf-8", newline="") as file:
            file.write("#########################################################\n")
            file.write("\t\tRECIBO DE CONTRASEÑAS\n")
            file.write("#########################################################\n")
            file.write("Usuario: " + self.__username + "\n\n")
            file.write("Sitios:\n\n")
            for pwd in self.__stored_passwords:
                file.write("\tSitio: " + pwd["web"] + "\n")
                file.write("\tNota: " + pwd["web_note"] + "\n")
                file.write("\n")
            file.write("#########################################################\n")
            file.write("\t\tFecha: " + now.strftime("%d/%m/%Y %H:%M:%S") + "\n")
            file.write("#########################################################\n")
        # Read the file's bytes
        with open(receipt_filename + ".txt", "rb") as file:
            data = file.read()
        # Sign the file
        signature = self.sign_file(data)
        # Save the signature
        with open(signature_filename + ".sig", "wb") as file:
            file.write(signature)

        # Verify the signature
        try:
            self.verify_file(data, signature)
        except Exception as ex:
            raise ex
        return True

    def sign_file(self, data):
        # Sign the file
        signature = self.__private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_receipt(self, receipt_filename, signature_filename):
        # Read the file's bytes
        with open(receipt_filename, "rb") as file:
            data = file.read()
        # Read the signature
        with open(signature_filename, "rb") as file:
            signature = file.read()
        # Verify the signature
        try:
            self.verify_file(data, signature)
        except Exception as ex:
            raise ex
        return True

    def verify_file(self, data, signature):
        # Verify the signature
        try:
            self.__private_key.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as ex:
            raise ValueError("La firma del documento no ha podido ser verificada") from ex
        return True

    def generate_certificate(self, pk_password):
        """
        Generates a certificate signing request (CSR) for the user
        :param pk_password: Password for the user's private key serialization
        :return:
        """
        # Create the user's directory in the pki folder
        if not os.path.exists(PKI_PATH + str(self.__user_id)):
            os.makedirs(PKI_PATH + str(self.__user_id))

        # Generate the user's private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Write the private key to the __serial_private_key attribute
        self.__serial_private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(pk_password.encode())
        )

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M")
        ])).sign(key, hashes.SHA256())

        # Write the CSR to a file in the user's directory
        with open(PKI_PATH + str(self.__user_id) + "/csr.pem", "wb") as file:
            file.write(csr.public_bytes(serialization.Encoding.PEM))

        # Write the CSR o the AC1/solicitudes directory
        with open(PKI_PATH + "AC1/solicitudes/" + str(self.__user_id) + ".pem", "wb") as file:
            file.write(csr.public_bytes(serialization.Encoding.PEM))

        # Generate the certificate using OpenSSL
        # Open the AC1 directory in the terminal
        os.system('cmd /k "cd ' + PKI_PATH + 'AC1"')
        os.system('cmd /k "openssl ca -in ./solicitudes/' + str(self.__user_id) +
                  '.pem -notext -config ./openssl_AC1.cnf"')

        # Enter the password for the CA


        # Copy the certificate to the user's directory
        # It is the file with the highest number in the nuevoscerts directory
        filename = max([int(f.split(".")[0]) for f in os.listdir(PKI_PATH + "AC1/nuevoscerts")])

        os.system('cmd /k "copy ' + PKI_PATH + 'AC1/nuevoscerts/' + str(self.__user_id) + '.pem ' +
                  PKI_PATH + str(self.__user_id) + '/cert.pem"')





    @property
    def username(self):
        """gets the username value"""
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

    def dump_user_info(self):
        """
        Function to be run ALWAYS before the user object is deleted from memory
        """
        # Before deleting the user, save the user and their passwords
        # We encrypt the passwords with Fernet using the user's password as key
        encrypted_passwords, self.__encryption_salt = self.auth_encrypt(self.__stored_passwords)
        PwdStore().save(str(encrypted_passwords), self.__user_id)
        # We add the users to the users file in the manager
        self.save_user()
        # We encrypt the users file with Fernet using the master password as key and save them
        self.__manager.auth_encrypt_users()
