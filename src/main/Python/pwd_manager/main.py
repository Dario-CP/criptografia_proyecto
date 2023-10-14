"""
Main file for the password manager.
"""
# ------------------------------------
from tkinter import *  # type: ignore
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
# ------------------------------------
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
    Button(window_user, text="Añadir contraseña", height="2", width="30", bg="#FFFFFF",command=add_password_window).pack()
    # Boton eliminar contraseña
    Button(window_user, text="Eliminar contraseña", height="2", width="30", bg="#FFFFFF", command=delete_password_window).pack()
    # Boton cerrar sesión
    Button(window_user, text="Log out", height="2", width="30", bg="#FFFFFF", command=logout).pack()
    data = user_actual.pwds()
    if data is not None:
        for pwd in data:
            Label(window_user, text="", bg=background_color).pack()
            Label(window_user, text=pwd, fg='#ffF', bg="#000000").pack()
    window_user.pack()


# VENTANA AÑADIR CONTRASEÑA DEL USUARIO
def add_password_window():
    """Ventana añadir contraseña"""
    # FORMULARIO DATOS AÑADIR UNA NUEVA CONTRASEÑA
    # Web
    Label(window_add_password, bg=background_color, fg='#ffF', text="Website * ").pack()
    Entry(window_add_password, textvariable=web).pack()
    # Contraseña de la web
    Label(window_add_password, bg=background_color, fg='#ffF', text="Password * ").pack()
    Entry(window_add_password, textvariable=web_password).pack()
    # Descripción/Nota sobre la web o contraseña
    Label(window_add_password, bg=background_color, fg='#ffF', text="Note").pack()
    Entry(window_add_password, textvariable=web_note).pack()
    # Add padding between input fields and button
    Label(window_add_password, text="", bg=background_color).pack()
    Button(window_add_password, text="Add", height="2", width="30", bg="#FFFFFF", command=add_password).pack()
    window_add_password.pack()


# VENTANA ELIMINAR CONTRASEÑA DEL USUARIO
def delete_password_window():
    """Ventana eliminar contraseña"""
    pass


# FUNCION IR PARA ATRAS
def back():
    window_register.forget()
    window_login.forget()
    window_home.pack()


# FUNCIÓN INICIAR SESIÓN
def login_user():
    """Iniciar sesion"""
    try:
        user_actual.login_user(username.get(), password.get())
        messagebox.showinfo(message="Sesión iniciada correctamente")
        window_login.forget()
        user_window()
    except ValueError as e:
        messagebox.showerror(message=e)


# FUNCION REGISTRAR USUARIO
def register_user():
    """Registrar usuario"""
    try:
        check_password(password.get())
        user_actual.register_user(username.get(), password.get())
        messagebox.showinfo(title='Registrado', message="Registrado correctamente")
        window_register.forget()
        user_window()
    except ValueError as e:
        messagebox.showerror(title='Error', message=e)


# FUNCION CERRAR SESIÓN USUARIO
def logout():
    """Cerrar sesión"""
    messagebox.showinfo(message="Sesión cerrada correctamente")
    user_actual.__del__()
    # Forget all labels and entries from the login
    window_login.forget()
    # Remove all labels and entries from the window_user
    for widget in window_user.winfo_children():
        widget.destroy()
    window_user.forget()
    window_register.forget()
    window_add_password.forget()
    # window_delete_password.forget()
    password.set("")
    username.set("")
    window_home.pack()


def check_password(passw):
    Password(passw).value


def add_password():
    """Añadir contraseña"""
    user_actual.add_password(web.get(), web_password.get(), web_note.get())
    messagebox.showinfo(message="Contraseña añadida correctamente")
    # Remove all labels and entries from the window_add_password
    for widget in window_add_password.winfo_children():
        widget.destroy()
    # Reset the values of the StringVars
    web.set("")
    web_password.set("")
    web_note.set("")
    # Remove all labels and entries from the window_user
    for widget in window_user.winfo_children():
        widget.destroy()
    user_window()


# ----CARACTERISTICAS VENTANA----
background_color = "#2D2D2D"
window_principal = tk.Tk()
window_principal.config(bg=background_color)
window_principal.geometry("1500x800")
window_principal.title("Gestor de contraseñas")

# ----VARIABES GLOBALES----
global username
global password
global web
global web_password
global web_note
global user_actual
username = StringVar()
password = StringVar()
web = StringVar()
web_password = StringVar()
web_note = StringVar()
user_actual = User()

# ----VENTANA HOME----
window_home = Frame(window_principal)
window_home.config(width=300, height=250, bg=background_color)
window_home.pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()
# Boton de iniciar sesión
Button(window_home, text="Log in", height="2", width="30", bg="#FFFFFF", command=login_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()
# Boton de registrar
Button(window_home, text="Register", height="2", width="30", bg="#FFFFFF", command=register_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()

# ----VENTANA LOG IN----
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

# ----VENTANA REGISTRAR----
window_register = Frame(window_principal)
window_register.config(width=300, height=250, bg=background_color)
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Button(window_register, text="Back", height="2", width="30", bg="#FFFFFF", command=back).pack()
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Label(window_register, text="Please enter details below to login", fg='#ffF', bg=background_color).pack()
Label(window_register, text="Password details:\n1.-At least 8 characters\n2.-At least 1 letter in caps\n3.-At least a "
                            "number\n4.-At least one special character (?!@$&*-.)", fg='#ffF',
                            bg=background_color, justify="left").pack()
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

# ----VENTANA AÑADIR CONTRASEÑA----
window_add_password = Frame(window_principal)
window_add_password.config(width=300, height=250, bg=background_color)

# ----VENTANA ELIMINAR CONTRASEÑA----

window_principal.mainloop()

# TODO: Corregir que se puedan generar ventanas infinitas de login y register
# TODO: Limpiar y comentar código
# TODO: Encriptación
