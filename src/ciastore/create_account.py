"""Create an account in an empty database."""

# Programmed by CoolCat467

__title__ = "Create Account"
__author__ = "CoolCat467"
__version__ = "0.0.0"

from ciastore import database, security, server


def run() -> None:
    """Prompt to create new admin account."""
    username = input("Username: ").lower().replace(" ", "")
    new_password = input("Password: ")
    users = database.load("records/users.json")
    if username in users:
        print("User already exists!")
        return
    server.create_uninitialized_account(username, "admin")
    users[username]["status"] = "created"
    users[username]["password"] = security.create_new_login_credentials(
        new_password,
        server.PEPPER,
    )
    users.write_file()


if __name__ == "__main__":
    print(f"{__title__} v{__version__}\nProgrammed by {__author__}.\n")
    run()
