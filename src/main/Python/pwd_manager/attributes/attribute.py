"""This module will describe the class to properly set the attributes"""
import re


class Attribute:
    _validation_pattern = r""
    _validation_error_message = ""
    _value = ""

    def __init__(self, attr_value):
        self._value = self._validate(attr_value)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, attr_value):
        self._value = self._validate(attr_value)

    def _validate(self, attr_value):
        registration_type_pattern = re.compile(self._validation_pattern)
        try:
            res = registration_type_pattern.fullmatch(attr_value)
            if not res:
                raise ValueError(self._validation_error_message)
        except TypeError:
            raise ValueError(self._validation_error_message)
        return attr_value
