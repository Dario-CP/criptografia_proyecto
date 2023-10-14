from pwd_manager.cfg.pwd_manager_config import JSON_FILES_PATH
from .json_store import JsonStore


class PwdStore(JsonStore):
    _FILE_PATH = JSON_FILES_PATH + "pwd_users/"
    _ID_FIELD = "user_name"

    def set_file_path(self, id):
        self._FILE_PATH += str(id)
        self._FILE_PATH += ".json"

    def save(self, data_list, id):
        self.set_file_path(id)
        super().save(data_list)

    def add_item(self, item, id):
        self.set_file_path(id)
        if not isinstance(item, dict):
            raise ValueError("Invalid object")
        super().add_item(item)

    def find_item(self, key_value, key=None):
        if key is None:
            key = self._ID_FIELD
        return super().find_item(key_value, key)

    def lists(self, id):
        self.set_file_path(id)
        lists = super().load()
        return lists
