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
from attributes.attribute_password import Password

global window_principal
global window_home
global window_login
global window_register
global window_user


# FUNCIÓN QUE CREA LA VENTANA REGISTRAR
def register_window():
    """Sign up window"""
    window_register.pack()
    # Esconder la ventana log in
    if window_login:
        window_login.forget()
        window_home.forget()

# FUNCIÓN QUE CREA LA VENTANA LOG IN
def login_window():
    """Log in window"""
    window_login.pack()
    # Esconder la ventana registrar
    if window_register:
        window_register.forget()
        window_home.forget()

# FUNCIÓN QUE CREA LA VENTANA DEL USUARIO
def user_window():
    """User window"""
    # ----VENTANA DE USUARIO----
    Label(window_user, text="Usuario: " + user_actual.username, fg='#ffF', bg=background_color).pack()
    Label(window_user, text="", bg=background_color).pack()
    # Boton añadir contraseña
    Button(window_user, text="Añadir contraseña", height="2", width="30", bg="#FFFFFF",
           command=añadir_contraseña).pack()
    # Boton eliminar contraseña
    Button(window_user, text="Eliminar contraseña", height="2", width="30", bg="#FFFFFF",
           command=eliminar_contraseña).pack()
    # Boton cerrar sesión
    Button(window_user, text="Log out", height="2", width="30", bg="#FFFFFF", command=logout).pack()
    window_user.pack()

# FUNCION IR PARA ATRAS
def back():
    window_register.forget()
    window_login.forget()
    window_home.pack()

# FUNCIÓN INICIAR SESIÓN
def login_user():
    """Iniciar sesion"""
    logged = user_actual.login_user(username.get(), password.get())
    if logged:
        messagebox.showinfo(message="Sesión iniciada correctamente")
        window_login.forget()
        user_window()
    else:
        messagebox.showerror(message="Error de inicio de sesión")

# FUNCION REGISTRAR USUARIO
def register_user():
    """Registrar usuario"""
    try:
        check_password(password.get())
        user_actual.register_user(username.get(), password.get())
        messagebox.showinfo(title='Registrado', message="Registrado correctamente")
        window_register.forget()
        user_window()
    except ValueError:
        messagebox.showerror(title='Error', message="Nombre de usuario ya registrado")

# FUNCION AÑADIR CONTRASEÑA DEL USUARIO
def añadir_contraseña():
    """Llama a la funcion añadir contraseña"""
    pass

# FUNCION ELIMINAR CONTRASEÑA DEL USUARIO
def eliminar_contraseña():
    """Llama a la funcion eliminar contraseña"""
    pass

# FUNCION CERRAR SESIÓN USUARIO
def logout():
    """Cerrar sesión"""
    messagebox.showinfo(message="Sesión cerrada correctamente")
    user_actual.__del__()
    window_login.forget()
    window_user.forget()
    window_register.forget()
    password.set("")
    username.set("")
    window_home.pack()

def check_password(passw):
    x = Password(passw).value



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
# Boton de iniciar sesión
Button(window_home, text="Log in", height="2", width="30", bg="#FFFFFF", command=login_window).pack()
Label(window_home,text="", bg=background_color, fg='#ffF').pack()
# Boton de registrar
Button(window_home, text="Register", height="2", width="30", bg="#FFFFFF", command=register_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()

#----VENTANA LOG IN----
window_login = Frame(window_principal)
window_login.config(width=300, height=250, bg=background_color)
Label(window_login, text="", bg=background_color, fg='#ffF').pack()
Button(window_login, text="Back", height="2", width="30", bg="#FFFFFF", command=back).pack()
Label(window_login, text="", bg=background_color, fg='#ffF').pack()
Label(window_login, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
Label(window_login, text="", bg=background_color).pack()
# FORMULARIO DATOS LOG IN
# Usuario
Label(window_login, bg=background_color, fg='#ffF', text="Username * ").pack()
Entry(window_login, textvariable=username).pack()
# Contraseña
Label(window_login, bg=background_color, fg='#ffF', text="Password * ").pack()
Entry(window_login, textvariable=password, show='*').pack()
Label(window_login, text="", bg=background_color).pack()
# Boton de log in
Button(window_login, text="log in", height="2", width="30", bg="#FFFFFF", command=login_user).pack()

#----VENTANA REGISTRAR----
window_register = Frame(window_principal)
window_register.config(width=300, height=250, bg=background_color)
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Button(window_register, text="Back", height="2", width="30", bg="#FFFFFF", command=back).pack()
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Label(window_register, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
Label(window_register, text="", bg=background_color).pack()
# FORMULARIO REGISTRO DE DATOS
# Usuario
Label(window_register, bg=background_color, fg='#ffF', text="Username * ").pack()
Entry(window_register, textvariable=username).pack()
# Contraseña
Label(window_register, bg=background_color, fg='#ffF', text="Password * ").pack()
Entry(window_register, textvariable=password, show='*').pack()
Label(window_register, text="", bg=background_color).pack()
# Boton de registrar
Button(window_register, text="sign up", height="2", width="30", bg="#FFFFFF", command=register_user).pack()

# ----VENTANA USUARIO----
window_user = Frame(window_principal)
window_user.config(width=300, height=250, bg=background_color)

window_principal.mainloop()

# TODO: Corregir que se puedan generar ventanas infinitas de login y register
# TODO: Limpiar y comentar código
# TODO: Encriptación
