#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Backups - Preform periodic backups of all records

"Preform periodic backups of all records"

# Programmed by CoolCat467

__title__ = "Backups"
__author__ = "CoolCat467"

import time
from os import path

import trio

from ciastore import database
from ciastore.logger import log


async def backup_database() -> None:
    """Backup records from database module"""
    for database_name in database.get_loaded():
        # Get folder and filename
        folder = path.dirname(database_name)
        orig_filename = path.basename(database_name)

        # Attempt to get list of [{filename}, {file end}]
        file_parts = orig_filename.rsplit(".", 1)
        if len(file_parts) == 2:
            # End exists
            name, end = file_parts
            # If is already a backup, do not backup the backup.
            # If this happens that is bad.
            if "bak" in end:
                continue
            end = f"{end}.bak"
        else:
            # If end not exist, just make it a backup file
            name = file_parts[0]
            end = "bak"

        # We have now gotten name and end, add time stamp to name
        name = time.strftime(f"{name}_(%Y_%m_%d)")
        filename = f"{name}.{end}"

        # Get full path of backup file
        backup_name = path.join(folder, "backup", filename)

        # Load up file to take backup of and new backup file
        instance = database.load(database_name)
        backup = database.load(backup_name)

        # Add contents of original to backup
        backup.update(instance)

        # Unload backup file which triggers it to write,
        # including creating folders if it has to
        database.unload(backup_name)


async def backup() -> None:
    """Backup all records"""
    log("Preforming backup")
    await backup_database()
    log("Backup complete")


async def periodic_backups() -> None:
    """Trigger periodic backups"""
    while True:
        # Do backup every 6 hours
        await trio.sleep(60 * 60 * 6)
        await backup()


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")