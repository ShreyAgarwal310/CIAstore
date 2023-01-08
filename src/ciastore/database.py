from typing import Any, Callable, Optional
from os import path, makedirs
import json
import weakref


_LOADED: dict[str, "Database"] = {}


class Database(dict[str, Any]):
    """Database dict with file read write functions"""

    __slots__ = ("file", "__weakref__")

    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file = file_path

        if path.exists(self.file):
            self.reload_file()

    def reload_file(self) -> None:
        """Reload database file"""
        with open(self.file, "r", encoding="utf-8") as file:
            self.update(json.load(file))

    def write_file(self) -> None:
        """Write database file"""
        folder = path.dirname(self.file)
        if not path.exists(folder):
            makedirs(folder, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as file:
            json.dump(self, file)


def __database_ref_dead(
    file_path: str,
) -> Callable[Optional["weakref.CallableProxyType[Database]"], None]:
    """Properly unload dead reference"""

    def ref_dead(dead_ref: Optional["weakref.CallableProxyType[Database]"]) -> None:
        unload(file_path)

    return ref_dead


def load(file_path: str) -> Database:
    """Load database from file path or return already loaded instance"""
    file = path.abspath(file_path)
    if not file in _LOADED:
        _LOADED[file] = Database(file)
    return weakref.proxy(_LOADED[file], __database_ref_dead(file))


def get_loaded() -> set[str]:
    """Return set of loaded database files"""
    return set(_LOADED)


def unload(file_path: str) -> None:
    """If database loaded, write file and unload"""
    file = path.abspath(file_path)
    if file not in get_loaded():
        return
    database = load(file)
    database.write_file()
    del _LOADED[file]


def unload_all() -> None:
    """Unload all loaded databases"""
    for file_path in get_loaded():
        unload(file_path)
