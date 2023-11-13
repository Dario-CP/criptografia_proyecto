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
    # Boton descargar recibo
    ###########################################
    # Boton cerrar sesión
    Button(window_user, text="Cerrar sesión", height="2", width="30", bg="#FFFFFF", command=logout).pack()
    data = user_actual.stored_passwords
    if data is not None:
        for pwd in data:
            Label(window_user, text="", bg=background_color).pack()
            # Place two rectangles on the screen, one for the website and one for the password

            # Website
            Label(window_user, text="Sitio: " + pwd["web"] + " ", fg='#ffF', bg=background_color).pack()
            # Password
            Label(window_user, text="Contraseña: " + pwd["web_password"] + " ", fg='#ffF', bg=background_color).pack()

            # Button to show the password
            # Button(window_user, text="Mostrar contraseña", height="2", width="30", bg="#FFFFFF", command=lambda: messagebox.showinfo(message=show_password(counter, data))).pack()

            # Note
            Label(window_user, text="Nota: " + pwd["web_note"], fg='#ffF', bg=background_color).pack()

    window_user.pack()

# VENTANA AÑADIR CONTRASEÑA DEL USUARIO
def add_password_window():
    """Ventana añadir contraseña"""
    # Remove all labels and entries from the window_add_password
    for widget in window_add_password.winfo_children():
        widget.destroy()
    window_delete_password.forget()
    # FORMULARIO DATOS AÑADIR UNA NUEVA CONTRASEÑA
    # Web
    Label(window_add_password, bg=background_color, fg='#ffF', text="Sitio * ").pack()
    Entry(window_add_password, textvariable=web).pack()
    # Contraseña de la web
    Label(window_add_password, bg=background_color, fg='#ffF', text="Contraseña * ").pack()
    Entry(window_add_password, textvariable=web_password).pack()
    # Descripción/Nota sobre la web o contraseña
    Label(window_add_password, bg=background_color, fg='#ffF', text="Nota").pack()
    Entry(window_add_password, textvariable=web_note).pack()
    # Add padding between input fields and button
    Label(window_add_password, text="", bg=background_color).pack()
    Button(window_add_password, text="Añadir", height="2", width="30", bg="#FFFFFF", command=add_password).pack()
    window_add_password.pack()

# VENTANA ELIMINAR CONTRASEÑA DEL USUARIO
def delete_password_window():
    """Ventana eliminar contraseña"""
    # Remove all labels and entries from the window_add_password
    for widget in window_delete_password.winfo_children():
        widget.destroy()
    window_add_password.forget()
    Label(window_delete_password, bg=background_color, fg='#ffF', text="Website * ").pack()
    Entry(window_delete_password, textvariable=web).pack()
    # Add padding between input fields and button
    Label(window_delete_password, text="", bg=background_color).pack()
    Button(window_delete_password, text="Eliminar", height="2", width="30", bg="#FFFFFF", command=delete_password).pack()
    window_delete_password.pack()

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
        user_actual.register_user(username.get(), password.get())
        messagebox.showinfo(title='Registrado', message="Registrado correctamente")
        window_register.forget()
        user_window()
    except ValueError as e:
        messagebox.showerror(title='Error', message=e)


# FUNCION CERRAR SESIÓN USUARIO
def logout():
    """Cerrar sesión"""

    # Delete the user_actual object and create a new one
    global user_actual
    user_actual.dump_user_info()
    user_actual = User()

    messagebox.showinfo(message="Sesión cerrada correctamente")

    # Forget all labels and entries from the login
    window_login.forget()

    # Remove all labels and entries from the window_user
    for widget in window_user.winfo_children():
        widget.destroy()
    window_user.forget()

    window_register.forget()

    # Remove all labels and entries from the window_add_password
    for widget in window_add_password.winfo_children():
        widget.destroy()
    window_add_password.forget()

    # Remove all labels and entries from the window_delete_password
    for widget in window_delete_password.winfo_children():
        widget.destroy()
    window_delete_password.forget()

    password.set("")
    username.set("")

    window_home.pack()

def add_password():
    """Añadir contraseña"""
    try:
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
        window_add_password.forget()
        user_window()
    except ValueError as e:
        messagebox.showerror(message=e)

def delete_password():
    """Añadir contraseña"""
    try:
        user_actual.delete_password(web.get())
        messagebox.showinfo(message="Contraseña eliminada correctamente")
        # Remove all labels and entries from the window_delete_password
        for widget in window_delete_password.winfo_children():
            widget.destroy()
        # Reset the values of the StringVars
        web.set("")
        # Remove all labels and entries from the window_user
        for widget in window_user.winfo_children():
            widget.destroy()
        window_delete_password.forget()
        user_window()
    except ValueError as e:
        messagebox.showerror(message=e)

def show_password(counter, data):
    # Find the password to delete
    return data[counter]["web_password"]

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
Button(window_home, text="Iniciar sesión", height="2", width="30", bg="#FFFFFF", command=login_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()
# Boton de registrar
Button(window_home, text="Registrarse", height="2", width="30", bg="#FFFFFF", command=register_window).pack()
Label(window_home, text="", bg=background_color, fg='#ffF').pack()

# ----VENTANA LOG IN----
window_login = Frame(window_principal)
window_login.config(width=300, height=250, bg=background_color)
Label(window_login, text="", bg=background_color, fg='#ffF').pack()
Button(window_login, text="Back", height="2", width="30", bg="#FFFFFF", command=back).pack()
Label(window_login, text="", bg=background_color, fg='#ffF').pack()
Label(window_login, text="Por favor introduzca los detalles debajo para iniciar sesión", fg='#ffF', bg=background_color).pack()
Label(window_login, text="", bg=background_color).pack()
# FORMULARIO DATOS LOG IN
# Usuario
Label(window_login, bg=background_color, fg='#ffF', text="Nombre de usuario * ").pack()
Entry(window_login, textvariable=username).pack()
# Contraseña
Label(window_login, bg=background_color, fg='#ffF', text="Contraseña * ").pack()
Entry(window_login, textvariable=password, show='*').pack()
Label(window_login, text="", bg=background_color).pack()
# Boton de log in
Button(window_login, text="Iniciar sesión", height="2", width="30", bg="#FFFFFF", command=login_user).pack()

# ----VENTANA REGISTRAR----
window_register = Frame(window_principal)
window_register.config(width=300, height=250, bg=background_color)
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Button(window_register, text="Atrás", height="2", width="30", bg="#FFFFFF", command=back).pack()
Label(window_register, text="", bg=background_color, fg='#ffF').pack()
Label(window_register, text="Por favor introduzca los detalles debajo para registrarse", fg='#ffF', bg=background_color).pack()
Label(window_register, text="Detalles de la contraseña:"
                            "\n1.-Al menos 8 caracteres"
                            "\n2.-Al menos 1 mayúscula"
                            "\n3.-Al menos un número"
                            "\n4.-Al menos un carácter especial (?!@$&*-.)",
                            fg='#ffF', bg=background_color, justify="left").pack()
Label(window_register, text="", bg=background_color).pack()
# FORMULARIO REGISTRO DE DATOS
# Usuario
Label(window_register, bg=background_color, fg='#ffF', text="Nombre de usuario * ").pack()
Entry(window_register, textvariable=username).pack()
# Contraseña
Label(window_register, bg=background_color, fg='#ffF', text="Contraseña * ").pack()
Entry(window_register, textvariable=password, show='*').pack()
Label(window_register, text="", bg=background_color).pack()
# Boton de registrar
Button(window_register, text="Registrarse", height="2", width="30", bg="#FFFFFF", command=register_user).pack()

# ----VENTANA USUARIO----
window_user = Frame(window_principal)
window_user.config(width=300, height=250, bg=background_color)

# ----VENTANA AÑADIR CONTRASEÑA----
window_add_password = Frame(window_principal)
window_add_password.config(width=300, height=250, bg=background_color)

# ----VENTANA ELIMINAR CONTRASEÑA----
window_delete_password = Frame(window_principal)
window_delete_password.config(width=300, height=250, bg=background_color)

window_principal.mainloop()
