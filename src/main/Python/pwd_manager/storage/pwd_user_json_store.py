from pwd_manager.cfg.pwd_manager_config import JSON_FILES_PATH
from .json_store import JsonStore

class PwdStore(JsonStore):
    _FILE_PATH = JSON_FILES_PATH
    _ID_FIELD = "user_name"

    def add_item(self, item, id):
        self._FILE_PATH += str(id)
        self._FILE_PATH += ".json"
        if not isinstance(item, dict):
            raise ValueError("Invalid object")
        super().add_item(item)

    def find_item(self, key_value, key=None):
        if key is None:
            key = self._ID_FIELD
        return super().find_item(key_value, key)