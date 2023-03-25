"""CSV Records - Read and write CSV files"""

# Programmed by CoolCat467

__title__ = "CSV Records"
__author__ = "CoolCat467"
__version__ = "0.0.0"


import csv
from os import makedirs, path
from pathlib import Path
from typing import Any

import trio

from ciastore.database import Table

_LOADED: dict[str, "CSVRecords"] = {}


class CSVRecords(dict[str, Any]):
    """Database dict with file read write functions"""

    __slots__ = ("file", "key_name", "__weakref__")

    def __init__(
        self, file_path: str | Path | trio.Path, key_name: str
    ) -> None:
        super().__init__()
        self.file = file_path
        self.key_name = key_name

        if path.exists(self.file):
            self.reload_file()

    def reload_file(self) -> None:
        """Reload database file"""
        with open(self.file, encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file, dialect="unix")
            keys = next(reader)
            for row in reader:
                entry = {}
                entry_name = ""
                for i, value in enumerate(row):
                    if not i:  # i == 0
                        entry_name = value
                    else:
                        entry[keys[i]] = value
                self[entry_name] = entry

    async def async_write_file(self) -> None:
        """Write database file asynchronously"""
        folder = trio.Path(path.dirname(self.file))
        if not await folder.exists():
            makedirs(folder, exist_ok=True)
        table = Table(self, self.key_name)
        async with await trio.open_file(
            self.file, "w", encoding="utf-8"
        ) as file:
            keys = table.keys()
            await file.write(",".join(keys))
            await file.write("\n")
            for entry_name, value in self.items():
                await file.write(entry_name)
                for key in keys:
                    if key == self.key_name:
                        continue
                    await file.write(f",{value.get(key, '')}")
                await file.write("\n")


#    @staticmethod
#    def _write_row(
#        values: Iterable[int | float | str],
#    ) -> Generator[str, None, None]:
#        for value in values:
#            if isinstance(value, str):
#                need_quote = False
#                if value.endswith("\n"):
#                    value = value.replace("\n", "")
#                    need_quote = True
#                if " " in value:
#                    need_quote = True
#                if need_quote:
#                    yield f'"{value}"'
#                else:
#                    yield value
#            elif isinstance(value, (int, float)):
#                yield str(value)


def load(file_path: str | Path, key_name: str | None = None) -> CSVRecords:
    """Load database from file path or return already loaded instance

    Key name can only be none if already loaded. If already loaded,
    has no effect."""
    file = path.abspath(file_path)
    if file not in _LOADED:
        if key_name is None:
            raise ValueError("key_name must not be None when loading records")
        _LOADED[file] = CSVRecords(file, key_name)
    return _LOADED[file]


def get_loaded() -> set[str]:
    """Return set of loaded database files"""
    return set(_LOADED)


async def unload(file_path: str | Path) -> None:
    """If database loaded, write file and unload"""
    file = path.abspath(file_path)
    if file not in get_loaded():
        return
    # must be loaded then so None is fine
    database = load(file, None)
    await database.async_write_file()
    del _LOADED[file]


async def unload_all() -> None:
    """Unload all loaded databases"""
    async with trio.open_nursery() as nursery:
        for file_path in get_loaded():
            nursery.start_soon(
                unload, file_path, name=f"csv_unload_{file_path}"
            )


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
