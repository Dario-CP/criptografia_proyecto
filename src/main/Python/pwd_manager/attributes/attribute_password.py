from .attribute import Attribute


class Password(Attribute):
    """Class for the attribute Password"""
    _validation_pattern = r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[?!@$&*-.]).{8,}$"
    _validation_error_message = "Contraseña no valida"
