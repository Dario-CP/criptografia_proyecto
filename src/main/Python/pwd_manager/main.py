"""
Main file for the password manager.
"""
#------------------------------------
from tkinter import * #type: ignore
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
#------------------------------------
from pwd_manager.register.register import Register
from pwd_manager.login.login import Login

global window_principal
global window_home
global window_login
global window_register



# ventana register
def register():
    """Sign up window"""
    window_register.pack()
    # Hide log in window
    if window_login:
        window_login.forget()

#ventana login
def login():
    """Log in window"""
    window_login.pack()
    if window_register:
        window_register.forget()

#login usuario
def logear_usuario():
    user = Login()
    user.login_user(enter_username.get(), enter_password.get())

#login usuario
def registrar_usuario():
    user = Register()
    user.register_user(enter_username.get(), enter_password.get())


#----CARACTERISTICAS VENTANA----
background_color = "#2D2D2D"
window_principal = tk.Tk()
window_principal.config(bg=background_color)
window_principal.geometry("1500x800")
window_principal.title("Gestor de contraseñas")

#----VARIABES GLOBALES----
global username
global password
username = StringVar()
password = StringVar()

#----VENTANA HOME----
window_home = Frame(window_principal)
window_home.config(width=300, height=250, bg=background_color)
window_home.pack()

Label(window_home, text="", bg=background_color, fg='#ffF').pack()
Button(window_home, text="Log in", height="2", width="30", bg="#FFFFFF", command=login).pack()
Label(window_home,text="", bg=background_color, fg='#ffF').pack()
Button(window_home, text="Register", height="2", width="30", bg="#FFFFFF", command=register).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()


#----VENTANA LOGIN----
window_login = Frame(window_principal)
window_login.config(width=300, height=250, bg=background_color)
Label(window_login, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
Label(window_login, text="", bg=background_color).pack()

#FORMULARIO DATOS LOG IN
#username
label_username = Label(window_login, bg=background_color, fg='#ffF', text="Username * ")
label_username.pack()
enter_username = Entry(window_login, textvariable=username)
enter_username.pack()
#password
label_password = Label(window_login, bg=background_color, fg='#ffF', text="Password * ")
label_password.pack()
enter_password = Entry(window_login, textvariable=password, show='*')
enter_password.pack()
Label(window_login, text="", bg=background_color).pack()
#boton log in
Button(window_login, text="log in", height="2", width="30", bg="#FFFFFF", command=logear_usuario).pack()

#----VENTANA REGISTRAR----
window_register = Frame(window_principal)
window_register.config(width=300, height=250, bg=background_color)
Label(window_register, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
Label(window_register, text="", bg=background_color).pack()
#FORMULARIO DATOS REGISTER
#username
label_username = Label(window_register, bg=background_color, fg='#ffF', text="Username * ")
label_username.pack()
enter_username = Entry(window_register, textvariable=username)
enter_username.pack()
#password
label_password = Label(window_register, bg=background_color, fg='#ffF', text="Password * ")
label_password.pack()
enter_password = Entry(window_register, textvariable=password, show='*')
enter_password.pack()
Label(window_register, text="", bg=background_color).pack()
#boton register
Button(window_register, text="sign up", height="2", width="30", bg="#FFFFFF", command=registrar_usuario).pack()

window_principal.mainloop()
