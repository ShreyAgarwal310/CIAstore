"""Server - Caught In the Act Server."""

__title__ = "Caught In the Act Server"
__author__ = "CSHS Members"
__version__ = "0.0.0"


import functools
import logging
import socket
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from logging.handlers import TimedRotatingFileHandler
from os import getenv, makedirs, path
from pathlib import Path
from typing import (
    Final,
    ParamSpec,
    TypeVar,
)
from urllib.parse import urlencode

import trio
from dotenv import load_dotenv
from hypercorn.config import Config
from hypercorn.trio import serve
from quart import request
from quart.templating import stream_template
from quart_auth import (
    AuthUser,
    QuartAuth,
    Unauthorized,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from quart_trio import QuartTrio
from werkzeug import Response as WKResponse
from werkzeug.exceptions import HTTPException

from ciastore import backups, csvrecords, database, elapsed, security

DOMAIN: str | None = getenv("DOMAIN", None)

FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"

ROOT_FOLDER = trio.Path(path.dirname(__file__))
CURRENT_LOG = ROOT_FOLDER / "logs" / "current.log"

if not path.exists(path.dirname(CURRENT_LOG)):
    makedirs(path.dirname(CURRENT_LOG))

logging.basicConfig(format=FORMAT, level=logging.DEBUG, force=True)
logging.getLogger().addHandler(
    TimedRotatingFileHandler(
        CURRENT_LOG,
        when="D",
        backupCount=60,
        encoding="utf-8",
        utc=True,
        delay=True,
    ),
)

load_dotenv()
PEPPER: Final = getenv("COOKIE_SECRET", "")


P = ParamSpec("P")
T = TypeVar("T")


# Stolen from WOOF (Web Offer One File), Copyright (C) 2004-2009 Simon Budig,
# available at http://www.home.unix-ag.org/simon/woof
# with modifications

# Utility function to guess the IP (as a string) where the server can be
# reached from the outside. Quite nasty problem actually.


def find_ip() -> str:
    """Guess the IP where the server can be found from the network."""
    # we get a UDP-socket for the TEST-networks reserved by IANA.
    # It is highly unlikely, that there is special routing used
    # for these networks, hence the socket later should give us
    # the IP address of the default route.
    # We're doing multiple tests, to guard against the computer being
    # part of a test installation.

    candidates: list[str] = []
    for test_ip in ("192.0.2.0", "198.51.100.0", "203.0.113.0"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((test_ip, 80))
        ip_addr: str = sock.getsockname()[0]
        sock.close()
        if ip_addr in candidates:
            return ip_addr
        candidates.append(ip_addr)

    return candidates[0]


app: Final = QuartTrio(
    __name__,
    static_folder="static",
    template_folder="templates",
)  # pylint: disable=invalid-name


# Attributes users might have and what they do:
# password : sha3_256 hash of password as string
# type : "student", "teacher", "manager", "admin"
# status : "not_created", "joining", "created_auto_password", "created"
#   Not created is when teacher has assigned points but student has not
#     set up account yet.
#   Joining is when student has visited sign up page and has join code
#     assigned, but has not used join code link yet.
#   Created Auto Password is when teacher account created with
#     automatic password, flag so account can be remade if forgotten
#     generated password.
#   Created is when join code link visited and account is verified.
# join_code : None or string of join code UUID
# join_code_expires : UNIX epoch time after which join code is expired


def get_user_by(**kwargs: str) -> set[str]:
    """Get set of usernames of given type."""
    users = database.load(Path(app.root_path) / "records" / "users.json")
    table = users.table("username")
    usernames: tuple[str, ...] = table["username"]

    result: set[str] = set(usernames)

    for raw_key, value in kwargs.items():
        key = raw_key.removesuffix("_")
        sub_result: set[str] = set()
        for index, entry_type in enumerate(table[key]):
            if entry_type == value:
                sub_result.add(usernames[index])
        result &= sub_result
    return result


def login_require_only(
    **attrs: str | set[str],
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Require login and some attribute match."""

    def get_wrapper(function: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        """Get handler wrapper."""

        @login_required
        @functools.wraps(function)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            """Make sure current user matches attributes."""
            if current_user.auth_id is None:
                raise Unauthorized()

            users = database.load(
                Path(app.root_path) / "records" / "users.json",
            )
            username = get_login_from_cookie_data(current_user.auth_id)

            if username is None or username not in users:
                logging.error(
                    f"Invalid login UUID {current_user.auth_id} " "in authenticated user",
                )
                logout_user()
                raise Unauthorized()

            user = users[username]
            for raw_key, raw_value in attrs.items():
                value = {raw_value} if isinstance(raw_value, str) else raw_value
                key = raw_key.removesuffix("_")
                if user.get(key) not in value:
                    raise Unauthorized()

            return await function(*args, **kwargs)

        return wrapper

    return get_wrapper


async def send_error(
    page_title: str,
    error_body: str,
    return_link: str | None = None,
) -> AsyncIterator[str]:
    """Stream error page."""
    return await stream_template(
        "error_page.html.jinja",
        page_title=page_title,
        error_body=error_body,
        return_link=return_link,
    )


async def get_exception_page(code: int, name: str, desc: str) -> tuple[AsyncIterator[str], int]:
    """Return Response for exception."""
    resp_body = await send_error(
        page_title=f"{code} {name}",
        error_body=desc,
    )
    return (resp_body, code)


def pretty_exception_name(exc: BaseException) -> str:
    """Make exception into pretty text (split by spaces)."""
    exc_str = repr(exc).split("(", 1)[0]
    words = []
    last = 0
    for idx, char in enumerate(exc_str):
        if char.islower():
            continue
        word = exc_str[last:idx]
        if not word:
            continue
        words.append(word)
        last = idx
    words.append(exc_str[last:])
    return " ".join(w for w in words if w not in {"Error", "Exception"})


def pretty_exception(function: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T | tuple[AsyncIterator[str], int]]]:
    """Make exception pages pretty."""

    @functools.wraps(function)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | tuple[AsyncIterator[str], int]:
        code = None
        name = "Exception"
        desc = None
        try:
            return await function(*args, **kwargs)
        except HTTPException as exception:
            logging.error(exception, exc_info=sys.exc_info())
            code = exception.code
            desc = exception.description
            name = exception.name
        except Exception as exception:
            logging.error(exception, exc_info=sys.exc_info())
            exc_name = pretty_exception_name(exception)
            name = f"Internal Server Error ({exc_name})"
        code = code or 500
        desc = desc or (
            "The server encountered an internal error and "
            + "was unable to complete your request. "
            + "Either the server is overloaded or there is an error "
            + "in the application."
        )
        return await get_exception_page(
            code,
            name,
            desc,
        )

    return wrapper


def create_login_cookie_data(username: str) -> str:
    """Generate UUID associated with a specific user.

    Only one instance of an account should be able
    to log in at any given time, subsequent will invalidate older
    sessions. This will make remembering instances easier
    """
    # Get login database
    logins = database.load(Path(app.root_path) / "records" / "login.json")

    # Make new random code until it does not exist
    while (code := str(uuid.uuid4())) in logins:
        continue

    # Make logins expire after a while
    expires = int(time.time()) + 2628000  # Good for 1 month

    # Write data back
    logins[code] = {
        "user": username,
        "expires": expires,
    }
    logins.write_file()
    return code


def get_login_from_cookie_data(code: str) -> str | None:
    """Get username from cookie data.

    If cookie data is invalid return None
    """
    # Get login database
    logins = database.load(Path(app.root_path) / "records" / "login.json")

    # Attempt to get entry for code. Using get instead of
    # "in" search and then index means is faster
    entry = logins.get(code, None)
    # If not exists or malformed entry, is bad
    if entry is None or not isinstance(entry, dict):
        return None
    # If expires not exist in entry or time expired, is bad and delete entry
    if entry.get("expires", 0) < int(time.time()):
        logging.info(f"Login UUID {code!r} expired")
        del logins[code]
        logins.write_file()
        return None
    # Otherwise attempt to return username field or is bad because malformed
    value = entry.get("user", None)
    assert isinstance(value, str) or value is None
    return value


def create_uninitialized_account(
    username: str,
    type_: str | None = None,
) -> None:
    """Create uninitialized account. If type is None do not set."""
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username in users:
        error = f"Attempted to create new account for {username} which exists"
        logging.error(error)
        return
    users[username] = {
        "status": "not_created",
    }
    if type_ is not None:
        users[username]["type"] = type_
    users.write_file()
    logging.info(f"Created uninitialized account {username!r}")


async def add_tickets_to_user(username: str, count: int) -> None:
    """Add ticket count to username. Create account if it doesn't exist."""
    assert count > 0, f"Use subtract_user_tickets instead of adding {count}"

    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        records[username] = {}

    current_tickets = get_user_ticket_count(username)
    assert isinstance(current_tickets, int)

    records[username]["tickets"] = current_tickets + count
    await records.async_write_file()
    logging.info(f"User {username!r} received {count!r} ticket(s)")


def get_user_ticket_count(username: str) -> int:
    """Get number of tickets user has at this time.

    Raises LookupError if username does not exist
    """
    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        raise LookupError(f"User {username!r} does not exist")

    raw_count: str | int = records[username].get("tickets", 0)
    if isinstance(raw_count, int):
        return raw_count
    assert isinstance(raw_count, str)
    if not raw_count.isdecimal():
        logging.error(
            f"Count from tickets was {raw_count!r} instead of decimal",
        )
        return 0
    return int(raw_count)


async def subtract_user_tickets(username: str, count: int) -> int:
    """Remove tickets from user. Return number of tickets left.

    Raises LookupError if username does not exist
    Raises ValueError if count is greater than number of tickets in account
    """
    assert count > 0, f"Use add_user_tickets instead of subtracting {count}"

    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        raise LookupError(f"User {username!r} does not exist")

    current_tickets = get_user_ticket_count(username)

    assert isinstance(current_tickets, int)
    new = current_tickets - count

    if new < 0:
        raise ValueError(
            f"Insufficiant tickets for user {username!r} to subtract {count}",
        )
    records[username]["tickets"] = new
    if new == 0:  # Maybe free up a bit of memory then, since default is zero
        del records[username]

    await records.async_write_file()
    logging.info(f"User {username!r} lost {count!r} ticket(s)")

    return new


def convert_joining(code: str) -> bool:
    """Convert joining record to student record."""
    # Get usernames with matching join code and who are joining
    users = database.load(Path(app.root_path) / "records" / "users.json")
    usernames = get_user_by(join_code=code, status="joining")
    if len(usernames) != 1:
        logging.info(f"Invalid code {code!r}")
        return False
    username = usernames.pop()

    # If expired, erase and continue
    now = int(time.time())
    expires = users[username].get("join_code_expires", 0)

    del users[username]["join_code"]
    del users[username]["join_code_expires"]

    if now > expires:
        users.write_file()

        delta = elapsed.get_elapsed(now - expires)
        logging.info(f"{username!r} join code expired by {delta}")
        return False

    users[username]["status"] = "created"
    users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    logging.info(f"User {username!r} logged in from join code")

    return True


# @app.get("/signup")
# async def signup_get() -> str | WKResponse:
#    """Handle sign up get including code register"""
#    # Get code from request arguments if it exists
#    code = request.args.get("code", None)
#    if code is not None:
#        success = convert_joining(code)
#        if success:
#            return app.redirect("/")
#        return await send_error(
#            "Signup Code Error",
#            "Signup code is invalid. It may have expired.",
#            request.url
#        )
#    return await stream_template(
#        "signup_get.html.jinja",
#    )


# @app.post("/signup")
# async def signup_post() -> WKResponse | str:
#    """Handle sign up form"""
#    multi_dict = await request.form
#    response = multi_dict.to_dict()
#
#    # Validate response
#    username = response.get("username", "")
#    password = response.get("password", "")
#
#    if bool(set(username) - set("0123456789")) or len(username) != 6:
#        return await send_error(
#            "Signup Error",
#            "Student usernames can only be numbers and must be exactly 6 "+
#            "digits long.",
#            request.url
#        )
#    if len(set(password)) < 7:
#        return await send_error(
#            "Signup Error",
#            "Password must have at least seven different characters "+
#            "for security reasons. Please use a more secure password.",
#            request.url
#        )
#
#    users = database.load(Path(app.root_path) / "records" / "users.json")
#
#    create_link = True
#
#    if username in users:
#        status = users[username].get("status", "not_created")
#        if status == "created":
#            return await send_error(
#                "Signup Error",
#                "A user with the requested username already exists",
#                request.url
#            )
#        if status == "joining":
#            now = int(time.time())
#            if users[username].get("join_code_expires", now + 5) < now:
#                create_link = False
#
#    # If not already in joining list, add and send code
#    email = f"{username}@class.lps.org"
#
#    if create_link:
#        table = users.table("username")
#        existing_codes = table["join_code"]
#        while (code := str(uuid.uuid4())) in existing_codes:
#            continue
#        link = (
#            app.url_for("signup_get", _external=True)
#            + "?"
#            + urlencode({"code": code})
#        )
#        expires = int(time.time()) + 10 * 60  # Expires in 10 minutes
#
#        expire_time = elapsed.get_elapsed(expires - int(time.time()))
#        title = "Please Verify Your Account"
#        message_body = "\n".join(
#            (
#                "There was a request to create a new account for the",
#                f"Caught In the Act Store with the username {username!r}.",
#                f"Please click {htmlgen.create_link(link, 'this link')}",
#                "to verify your account.",
#                "",
#                "If you did not request to make an account, please ignore",
#                f"this message. This link will expire in {expire_time}.",
#            )
#        )
#        sendmail.send(email, title, message_body)
#
#        if username not in users:
#            create_uninitialized_account(username)
#
#        users[username].update(
#            {
#                "password": security.create_new_login_credentials(
#                    password, PEPPER
#                ),
#                "email": users[username].get("email", email),
#                "type": users[username].get("type", "student"),
#                "status": "joining",
#                "join_code": code,
#                "join_code_expires": expires,
#            }
#        )
#        users.write_file()
#        logging.info(f"User {username!r} signed up")
#
#    return await stream_template(
#        "signup_post.html.jinja",
#        email=email,
#    )


@app.get("/login")
async def login_get() -> AsyncIterator[str]:
    """Get login page."""
    return await stream_template(
        "login_get.html.jinja",
    )


@app.post("/login")
async def login_post() -> AsyncIterator[str] | WKResponse:
    """Handle login form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return await send_error(
            "Login Error",
            "Username or password field not found",
            request.url,
        )

    # Check Credentials here, e.g. username & password.
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username not in users:
        return await send_error(
            "Login Error",
            "Username or password is invalid.",
            request.url,
        )

    if users[username].get("type", "student") == "student":
        return await send_error(
            "Login Error",
            "Students are not allowed to log in at this time.",
            request.url,
        )

    database_value = users[username].get("password", None)
    if database_value is None:
        return await send_error(
            "Login Error",
            "User data is missing password field (Please report to CSHS).",
            request.url,
        )
    if not await security.compare_hash(password, database_value, PEPPER):
        # Bad password
        return await send_error(
            "Login Error",
            "Username or password is invalid.",
            request.url,
        )

    # Make sure to change status of auto password accounts
    if users[username].get("status") == "created_auto_password":
        users[username]["status"] = "created"
        users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    logging.info(f"User {username!r} logged in")
    # print(f"{current_user = }")

    return app.redirect("/")


@app.get("/logout")
async def logout() -> WKResponse:
    """Handle logout."""
    if await current_user.is_authenticated:
        code = current_user.auth_id
        assert code is not None
        username = get_login_from_cookie_data(code)
        if username is not None:
            logging.info(f"User {username!r} ({code}) logged out")
        else:
            logging.error(f"Invalid UUID {code} logged out")
    logout_user()
    return app.redirect("login")


# @app.get("/user_data")
# @login_required
# async def user_data_route() -> WKResponse | Response:
#    """Dump user data
#
#    Warning, potential security issue, do not run in production"""
#    assert current_user.auth_id is not None
#    users = database.load(Path(app.root_path) / "records" / "users.json")
#    username = get_login_from_cookie_data(current_user.auth_id)
#
#    if username is None or username not in users:
#        logging.error(
#            f"Invalid login UUID {current_user.auth_id} "
#            "in authenticated user",
#        )
#        logout_user()
#        return app.redirect("login")
#    user = users[username] | {"username": username}
#    logging.debug(f"Record dump for {username!r}")
#    return Response(
#        json.dumps(user, sort_keys=True),
#        content_type="application/json",
#    )


@app.get("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager", "admin"})
async def add_tickets_get() -> AsyncIterator[str]:
    """Add tickets page for teachers."""
    return await stream_template(
        "add_tickets_get.html.jinja",
    )


@app.post("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager", "admin"})
async def add_tickets_post() -> AsyncIterator[str]:
    """Handle post for add tickets form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    student_id = response.get("id", "")
    ticket_count_raw = response.get("ticket_count", "")

    try:
        if not ticket_count_raw.isdigit():
            raise ValueError
        ticket_count = int(ticket_count_raw)
        if ticket_count < 1 or ticket_count > 10:
            raise ValueError
    except ValueError:
        return await send_error(
            "Ticket Count Error",
            "Ticket count is not in range.",
            request.url,
        )

    await add_tickets_to_user(student_id, ticket_count)

    plural = "" if ticket_count == 1 else "s"
    return await stream_template(
        "add_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        student_id=student_id,
    )


@app.get("/subtract-tickets")
@pretty_exception
@login_require_only(type_={"manager", "admin"})
async def subtract_tickets_get() -> AsyncIterator[str]:
    """Subtract tickets page for managers."""
    return await stream_template(
        "subtract_tickets_get.html.jinja",
    )


@app.post("/subtract-tickets")
@pretty_exception
@login_require_only(type_={"manager", "admin"})
async def subtract_tickets_post() -> AsyncIterator[str]:
    """Handle post for subtract tickets form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    student_id = response.get("id", "")
    ticket_count_raw = response.get("ticket_count", "")

    try:
        if not ticket_count_raw.isdigit():
            raise ValueError
        ticket_count = int(ticket_count_raw)
        if ticket_count < 1 or ticket_count > 100:
            raise ValueError
    except ValueError:
        return await send_error(
            "Ticket Count Error",
            "Ticket count is not in range.",
            request.url,
        )

    try:
        tickets_left = await subtract_user_tickets(student_id, ticket_count)
    except LookupError:
        # Username not exist
        return await send_error(
            "Not Enough Tickets Error",
            "Requested student has zero tickets.",
            request.url,
        )
    except ValueError:
        # Count > number of tickets in account
        return await send_error(
            "Not Enough Tickets Error",
            "Student does not have enough tickets for the requested " + "transaction",
            request.url,
        )

    plural = "" if ticket_count == 1 else "s"
    plural_left = "" if tickets_left == 1 else "s"
    return await stream_template(
        "subtract_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        plural_left=plural_left,
        student_id=student_id,
        tickets_left=tickets_left,
    )


@app.get("/settings")
@pretty_exception
@login_required
async def settings_get() -> AsyncIterator[str]:
    """Handle settings page get request."""
    return await stream_template(
        "settings_get.html.jinja",
    )


@app.get("/settings/change-password")
@pretty_exception
@login_required
async def settings_change_password_get() -> AsyncIterator[str]:
    """Handle setting page for password change get."""
    return await stream_template(
        "settings_change_password_get.html.jinja",
    )


@app.post("/settings/change-password")
@pretty_exception
@login_required
async def settings_password_post() -> AsyncIterator[str] | WKResponse:
    """Handle password change form."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    username = get_login_from_cookie_data(current_user.auth_id)

    if username is None or username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} " "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    current_password = response.get("current_password", "")
    new_password = response.get("new_password", "")

    if not current_password or not new_password:
        return await send_error(
            "Request Error",
            "Current password or new password field not found.",
            request.url,
        )

    # Check Credentials here, e.g. username & password.
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username not in users:
        logout_user()
        return app.redirect("login")

    if not await security.compare_hash(
        current_password,
        users[username]["password"],
        PEPPER,
    ):
        # Bad password
        logging.info(
            f"{username!r} did not enter own password in " + "change password",
        )
        return await send_error(
            "Password Does Not Match Error",
            "Entered password does not match current password.",
            request.url,
        )

    users[username]["password"] = security.create_new_login_credentials(
        new_password,
        PEPPER,
    )
    users.write_file()
    logging.info(f"{username!r} changed their password")

    return await stream_template(
        "settings_change_password_post.html.jinja",
    )


@app.get("/invite-teacher")
@pretty_exception
@login_require_only(type_="admin")
async def invite_teacher_get() -> AsyncIterator[str]:
    """Create new teacher account."""
    return await stream_template(
        "invite_teacher_get.html.jinja",
    )


@app.post("/invite-teacher")
@pretty_exception
@login_require_only(type_="admin")
async def invite_teacher_post() -> AsyncIterator[str] | WKResponse:
    """Invite teacher form post handling."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} " "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )
    length = len(new_account_username)
    if length < 3 or length > 16:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )

    possible_name = set("abcdefghijklmnopqrstuvwxyz23456789")
    if bool(set(new_account_username) - possible_name):
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )

    users = database.load(Path(app.root_path) / "records" / "users.json")

    if new_account_username in users and users[new_account_username]["status"] != "created_auto_password":
        return await send_error(
            "Invite User Error",
            "An account with the requested username already exists",
            request.url,
        )

    password = security.create_new_password(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "teacher",
        "status": "created_auto_password",
    }

    users.write_file()

    logging.info(
        f"{creator_username!r} invited {new_account_username!r} as teacher",
    )

    return await stream_template(
        "invite_teacher_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


@app.get("/invite-manager")
@pretty_exception
@login_require_only(type_="admin")
async def invite_manager_get() -> AsyncIterator[str]:
    """Create a new manager account."""
    return await stream_template(
        "invite_manager_get.html.jinja",
    )


@app.post("/invite-manager")
@pretty_exception
@login_require_only(type_="admin")
async def invite_manager_post() -> AsyncIterator[str] | WKResponse:
    """Invite manager form post handling."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} " "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )
    length = len(new_account_username)
    if length < 3 or length > 16:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )

    possible_name = set("abcdefghijklmnopqrstuvwxyz23456789")
    if bool(set(new_account_username) - possible_name):
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long " + "and cannot contain special characters",
            request.url,
        )

    users = database.load(Path(app.root_path) / "records" / "users.json")

    if new_account_username in users and users[new_account_username]["status"] != "created_auto_password":
        return await send_error(
            "Invite User Error",
            "An account with the requested username already exists",
            request.url,
        )

    password = security.create_new_password(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "manager",
        "status": "created_auto_password",
    }

    users.write_file()

    logging.info(
        f"{creator_username!r} invited {new_account_username!r} as manager",
    )

    return await stream_template(
        "invite_manager_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


@pretty_exception
async def ticket_get_form() -> AsyncIterator[str]:
    """Generate form for ticket GET when no ID given."""
    return await stream_template(
        "ticket_form.html.jinja",
    )


@pretty_exception
async def ticket_count_page(username: str) -> AsyncIterator[str]:
    """Ticket count page for given username."""
    user_type = None

    if current_user.auth_id is not None:
        users = database.load(Path(app.root_path) / "records" / "users.json")
        logged_in_username = get_login_from_cookie_data(current_user.auth_id)

        if logged_in_username is not None and logged_in_username in users:
            user_type = users[logged_in_username].get("type")

    try:
        count = get_user_ticket_count(username)
    except LookupError:
        count = 0

    user_link = app.url_for("tickets_get") + "?" + urlencode({"id": username})

    return await stream_template(
        "ticket_count_page.html.jinja",
        username=repr(username),
        count=repr(count),
        user_link=user_link,
        user_type=user_type,
    )


@app.get("/tickets")
@pretty_exception
async def tickets_get() -> AsyncIterator[str]:
    """Tickets view page."""
    # Get username from request arguments if it exists
    username = request.args.get("id", None)

    if not username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")) or len(username) != 6:
        # If username has any character except 0-9, bad
        return await send_error(
            "User Error",
            "Username is invalid.",
            request.url,
        )

    return await ticket_count_page(username)


@app.post("/tickets")
@pretty_exception
async def tickets_post() -> AsyncIterator[str]:
    """Invite teacher form post handling."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    username = response.get("student_id", None)

    if not username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")):
        # If username has any character except 0-9, bad
        print(f"{username!r} bad")
        return await ticket_get_form()

    return await ticket_count_page(username)


@app.get("/")
async def root_get() -> AsyncIterator[str] | WKResponse:
    """Handle main page GET request."""
    # print(f"{current_user = }")

    user_name = ""
    user_type = ""
    if await current_user.is_authenticated:
        users = database.load(Path(app.root_path) / "records" / "users.json")
        assert current_user.auth_id is not None
        loaded_user = get_login_from_cookie_data(current_user.auth_id)

        if loaded_user is None or loaded_user not in users:
            logging.error(
                f"Invalid login UUID {current_user.auth_id} " "in authenticated user",
            )
            logout_user()
            return app.redirect("login")
        user_name = loaded_user

        user = users[user_name]

        user_type = user["type"]

    return await stream_template(
        "root_get.html.jinja",
        user_name=user_name,
        user_type=user_type,
    )


@app.before_serving
async def startup() -> None:
    """Schedule backups."""
    app.add_background_task(backups.periodic_backups)


async def run_async(
    root_dir: str,
    port: int,
    *,
    ip_addr: str | None = None,
    cookie_secret: str | None = None,
    localhost: bool = False,
) -> None:
    """Asynchronous Entry Point."""
    if ip_addr is None:
        ip_addr = "0.0.0.0"  # noqa: S104  # Binding to all interfaces
        if not localhost:
            ip_addr = find_ip()

    try:
        # Add more information about the address
        location = f"{ip_addr}:{port}"

        config = {
            "bind": [location],
            "worker_class": "trio",
        }
        if DOMAIN:
            config["certfile"] = f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
            config["keyfile"] = f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem"
        else:
            app.config["QUART_AUTH_COOKIE_SECURE"] = False
        app.config["QUART_AUTH_COOKIE_SAMESITE"] = "Strict"
        app.config["SERVER_NAME"] = location

        app.jinja_options = {
            "trim_blocks": True,
            "lstrip_blocks": True,
        }

        app.add_url_rule("/<path:filename>", "static", app.send_static_file)
        app.secret_key = cookie_secret

        config_obj = Config.from_mapping(config)

        QuartAuth(app)

        proto = "http" if not DOMAIN else "https"
        print(f"Serving on {proto}://{location}\n(CTRL + C to quit)")

        await serve(app, config_obj)
    except OSError:
        logging.error(f"Cannot bind to IP address '{ip_addr}' port {port}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Shutting down from keyboard interrupt")


def run() -> None:
    """Handle synchronous entry point."""
    root_dir = path.dirname(__file__)
    port = 6002

    cookie_secret: Final = getenv("COOKIE_SECRET")

    if cookie_secret is None:
        print(
            """\nNo cookie secret set!
Either add ".env" file in server folder with COOKIE_SECRET=<token here> line,
or set COOKIE_SECRET environment variable.""",
        )
        return

    hostname: Final = getenv("HOSTNAME", "None")

    ip_address = None
    if hostname != "None":
        ip_address = hostname

    local = "--local" in sys.argv[1:]

    trio.run(
        functools.partial(
            run_async,
            root_dir,
            port,
            cookie_secret=cookie_secret,
            ip_addr=ip_address,
            localhost=local,
        ),
        restrict_keyboard_interrupt_to_checkpoints=True,
    )


def main() -> None:
    """Call run after setup."""
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    try:
        logging.captureWarnings(True)
        try:
            run()
        finally:
            database.unload_all()
    finally:
        logging.shutdown()


if __name__ == "__main__":
    main()
