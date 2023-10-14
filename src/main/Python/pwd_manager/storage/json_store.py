"""
Module for the JsonStore class
"""
import json


class JsonStore:
    """
    Class for the Json storage
    """
    _FILE_PATH = ""
    _ID_FIELD = ""

    def __init__(self):
        pass

    def load(self):
        """ Loads the data from the file """
        # first read the file
        try:
            with open(self._FILE_PATH, "r", encoding="utf-8", newline="") as file:
                data_list = json.load(file)
        except FileNotFoundError:
            # file is not found , so  init my data_list
            data_list = []
        except json.JSONDecodeError as exception_raised:
            raise ValueError("JSON Decode Error - Wrong JSON Format")\
                from exception_raised

        return data_list

    def save(self, data_list):
        """ Saves the data to the file """
        try:
            with open(self._FILE_PATH, "w", encoding="utf-8", newline="") as file:
                json.dump(data_list, file, indent=2)
        except FileNotFoundError as ex:
            raise ValueError("Wrong file or file path") from ex

    def add_item(self, item):
        """ Adds an item to the data list """
        # create data_list
        data_list = self.load()
        # add item to data_list
        data_list.append(item)
        # save the data_list
        self.save(data_list)

    def find_item(self, key_value, key=None):
        """ Finds an item with key_value value """
        data_list = self.load()
        if key is None:
            key = self._ID_FIELD
        for item in data_list:
            if item[key] == key_value:
                return item
        return None

    # get all the items with key_value value
    def find_items_list(self, key_value, key=None):
        """ Finds all items with key_value value """
        data_list = self.load()
        if key is None:
            key = self._ID_FIELD

        data_list_result = []
        for item in data_list:
            if item[key] == key_value:
                data_list_result.append(item)
        return data_list_result

    def delete_item(self, key_value, key=None):
        """ Deletes an item with key_value value """
        data_list = self.load()
        if key is None:
            key = self._ID_FIELD
        for item in data_list:
            if item[key] == key_value:
                data_list.remove(item)
                self.save(data_list)
                return True
        return False

    def update_item(self, key_value, new_item, key=None):
        """ Updates an item with key_value value """
        data_list = self.load()
        if key is None:
            key = self._ID_FIELD
        for item in data_list:
            if item[key] == key_value:
                data_list.remove(item)
                data_list.append(new_item)
                self.save(data_list)
                return True
        return False
