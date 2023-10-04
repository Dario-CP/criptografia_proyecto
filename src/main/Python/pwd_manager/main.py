"""
Main file for the password manager.
"""
#------------------------------------
from tkinter import * #type: ignore
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
#------------------------------------
from pwd_manager.user.user import User

global window_principal
global window_home
global window_login
global window_register
global window_user





# ventana register
def register_window():
    """Sign up window"""
    # ----VENTANA REGISTRAR----
    Label(window_register, text="", bg=background_color, fg='#ffF').pack()
    Button(window_register, text="Log in", height="2", width="30", bg="#FFFFFF", command=login_window).pack()
    Label(window_register, text="", bg=background_color, fg='#ffF').pack()
    Label(window_register, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
    Label(window_register, text="", bg=background_color).pack()
    # FORMULARIO DATOS REGISTER
    # username
    Label(window_register, bg=background_color, fg='#ffF', text="Username * ").pack()
    Entry(window_register, textvariable=username).pack()
    # password
    Label(window_register, bg=background_color, fg='#ffF', text="Password * ").pack()
    Entry(window_register, textvariable=password, show='*').pack()
    Label(window_register, text="", bg=background_color).pack()
    # boton register
    Button(window_register, text="sign up", height="2", width="30", bg="#FFFFFF", command=register_user).pack()
    window_register.pack()
    # Hide log in window
    if window_login:
        window_login.forget()
        window_home.forget()

#ventana login
def login_window():
    """Log in window"""
    # ----VENTANA LOGIN----
    Label(window_login, text="", bg=background_color, fg='#ffF').pack()
    Button(window_login, text="Register", height="2", width="30", bg="#FFFFFF", command=register_window).pack()
    Label(window_login, text="", bg=background_color, fg='#ffF').pack()
    Label(window_login, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
    Label(window_login, text="", bg=background_color).pack()
    # FORMULARIO DATOS LOG IN
    # username
    Label(window_login, bg=background_color, fg='#ffF', text="Username * ").pack()
    Entry(window_login, textvariable=username).pack()
    # password
    Label(window_login, bg=background_color, fg='#ffF', text="Password * ").pack()
    Entry(window_login, textvariable=password, show='*').pack()
    Label(window_login, text="", bg=background_color).pack()
    # boton log in
    Button(window_login, text="log in", height="2", width="30", bg="#FFFFFF", command=login_user).pack()
    window_login.pack()
    if window_register:
        window_register.forget()
        window_home.forget()

def user_window():
    # ----VENTANA DE USUARIO----
    window_user = Frame(window_principal)
    window_user.config(width=300, height=250, bg=background_color)
    Label(window_user, text=user_actual.username, fg='#ffF', bg=background_color).pack()
    Label(window_user, text="", bg=background_color).pack()
    # boton register
    Button(window_user, text="Añadir contraseña", height="2", width="30", bg="#FFFFFF",
           command=añadir_contraseña).pack()
    Button(window_user, text="Eliminar contraseña", height="2", width="30", bg="#FFFFFF",
           command=eliminar_contraseña).pack()
    # boton log out
    # Button(window_user, text="Log out", height="2", width="30", bg="#FFFFFF", command=
    window_user.pack()

# login user
def login_user():
    logged = user_actual.login_user(username.get(), password.get())
    if logged:
        messagebox.showinfo(message="Sesión iniciada correctamente")
        window_login.forget()
        user_window()
    else:
        messagebox.showerror(message="Error de inicio de sesión")

# register user
def register_user():
    try:
        user_actual.register_user(username.get(), password.get())
        messagebox.showinfo(title='Registrado', message="Registrado correctamente")
        window_register.forget()
        user_window()

    except ValueError:
        messagebox.showerror(title='Error', message="Nombre de usuario ya registrado")


def añadir_contraseña():
    pass

def eliminar_contraseña():
    pass

def logout():
    user.__del__()



#----CARACTERISTICAS VENTANA----
background_color = "#2D2D2D"
window_principal = tk.Tk()
window_principal.config(bg=background_color)
window_principal.geometry("1500x800")
window_principal.title("Gestor de contraseñas")

#----VARIABES GLOBALES----
global username
global password
global user_actual
username = StringVar()
password = StringVar()
user_actual = User()

#----VENTANA HOME----
window_home = Frame(window_principal)
window_home.config(width=300, height=250, bg=background_color)
window_home.pack()

Label(window_home, text="", bg=background_color, fg='#ffF').pack()
Button(window_home, text="Log in", height="2", width="30", bg="#FFFFFF", command=login_window).pack()
Label(window_home,text="", bg=background_color, fg='#ffF').pack()
Button(window_home, text="Register", height="2", width="30", bg="#FFFFFF", command=register_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()

window_login = Frame(window_principal)
window_login.config(width=300, height=250, bg=background_color)

window_register = Frame(window_principal)
window_register.config(width=300, height=250, bg=background_color)


window_principal.mainloop()

# TODO: Corregir que se puedan generar ventanas infinitas de login y register
# TODO: Limpiar y comentar código
# TODO: Encriptación
