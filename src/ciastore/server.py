#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Server - Caught In the Act Server

"Caught In the Act Server"


__title__ = "Caught In the Act Server"
__author__ = "CoolCat467"
__version__ = "0.0.0"


import functools
import json
import math
import secrets
import socket
import sys
import time
import uuid
import warnings
from os import getenv, makedirs, path
from pathlib import Path
from typing import (Any, AsyncIterator, Awaitable, Callable, Final, TypeVar,
                    cast)
from urllib.parse import urlencode

import trio
from dotenv import load_dotenv
from hypercorn.config import Config
from hypercorn.trio import serve
from jinja2 import Template
from quart import Response, request
from quart.templating import render_template as quart_render_template
from quart.templating import stream_template as quart_stream_template
from quart_auth import (AuthManager, AuthUser, Unauthorized, current_user,
                        login_required, login_user, logout_user)
from quart_trio import QuartTrio
from werkzeug import Response as wkresp
from werkzeug.exceptions import HTTPException

from ciastore import database, elapsed, security

load_dotenv()
DOMAIN: str | None = None
PEPPER: Final = getenv("COOKIE_SECRET", "")


def log(message: str, level: int = 1, log_dir: str | None = None) -> None:
    "Log a message to console and log file."
    levels = ["DEBUG", "INFO", "ERROR"]

    if log_dir is None:
        log_dir = path.join(path.dirname(__file__), "logs")
    if not path.exists(log_dir):
        makedirs(log_dir, exist_ok=True)
    filename = time.strftime("log_%Y_%m_%d.log")
    log_file = path.join(log_dir, filename)

    log_level = levels[min(max(0, level), len(levels) - 1)]
    log_time = time.asctime()
    log_message_text = message.encode("unicode_escape").decode("utf-8")

    log_msg = f"[{__title__}] [{log_time}] [{log_level}] {log_message_text}"

    if not path.exists(log_file):
        with open(log_file, mode="w", encoding="utf-8") as file:
            file.close()
    with open(log_file, mode="a", encoding="utf-8") as file:
        file.write(f"{log_msg}\n")
        file.close()
    print(log_msg)


# Stolen from WOOF (Web Offer One File), Copyright (C) 2004-2009 Simon Budig,
# avalable at http://www.home.unix-ag.org/simon/woof
# with modifications

# Utility function to guess the IP (as a string) where the server can be
# reached from the outside. Quite nasty problem actually.


def find_ip() -> str:
    """Guess the IP where the server can be found from the network"""
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
AuthManager(app)


# Attributes users might have and what they do:
# password : sha3_256 hash of password as string
# type : "student", "teacher"
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
# tickets : Number of tickets account has


def get_user_by(**kwargs: str) -> set[str]:
    """Get set of usernames of given type"""
    users = database.load(app.root_path / "records" / "users.json")
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


Handler = TypeVar(
    "Handler",
    bound=Callable[
        ..., Awaitable[str | AsyncIterator[str] | wkresp | Response]
    ],
)


def login_require_only(
    **attrs: str | set[str],
) -> Callable[[Handler], Handler]:
    """Require login and some attribute match."""

    def get_wrapper(function: Handler) -> Handler:
        """Get handler wrapper"""

        @login_required
        @functools.wraps(function)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Make sure current user matches attributes"""

            if current_user.auth_id is None:
                raise Unauthorized()

            users = database.load(app.root_path / "records" / "users.json")
            username = get_login_from_cookie_data(current_user.auth_id)

            if username is None or username not in users:
                log(
                    f"Invalid login UUID {current_user.auth_id} "
                    "in authenticated user",
                    2,
                )
                logout_user()
                raise Unauthorized()

            user = users[username]
            for raw_key, raw_value in attrs.items():
                if isinstance(raw_value, str):
                    value = set((raw_value,))
                else:
                    value = raw_value
                key = raw_key.removesuffix("_")
                if user.get(key) not in value:
                    raise Unauthorized()

            return await function(*args, **kwargs)

        return cast(Handler, wrapper)

    return get_wrapper


async def render_template(
    template_name_or_list: str | list[str], **context: Any
) -> str:
    """Render the template with the context given.

    Arguments:
        template_name_or_list: Template name to render of a list of
            possible template names.
        context: The variables to pass to the template.

    Patched to remove blank lines left by jinja statements"""
    content = await quart_render_template(template_name_or_list, **context)
    new_content = []
    for line in content.splitlines():
        new_line = line.rstrip()
        if not new_line:
            continue
        new_content.append(new_line)
    return "\n".join(new_content)


async def stream_template(
    template_name_or_list: str | Template | list[str | Template],
    **context: Any,
) -> AsyncIterator[str]:
    """Render a template by name with the given context as a stream.

    This returns an iterator of strings, which can be used as a
    streaming response from a view.

    Arguments:
        template_name_or_list: The name of the template to render. If a
            list is given, the first name to exist will be rendered.
        context: The variables to make available in the template.

    Patched to remove blank lines left by jinja statements"""
    # Generate stream in this async context block before context is lost
    stream = await quart_stream_template(template_name_or_list, **context)

    # Create async generator filter
    async def generate() -> AsyncIterator[str]:
        async for chunk in stream:
            for line in chunk.splitlines(True):
                if not line.rstrip():
                    continue
                yield line

    return generate()


async def get_exception_page(code: int, name: str, desc: str) -> Response:
    """Return Response for exception"""
    resp_body = await render_template(
        "exception_page.html.jinja",
        code=code,
        name=name,
        desc=desc,
    )
    return Response(resp_body, status=code)


def pretty_exception(function: Handler) -> Handler:
    """Make exception pages pretty"""

    @functools.wraps(function)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await function(*args, **kwargs)
        except HTTPException as exception:
            code = exception.code or 404
            desc = exception.description or "An error occured"
            return await get_exception_page(
                code,
                exception.name,
                desc,
            )

    return cast(Handler, wrapper)


def create_login_cookie_data(username: str) -> str:
    """Generate UUID accociated with a specific user

    Only one instance of an account should be able
    to log in at any given time, subsequent will invalidate older
    sessions. This will make remembering instances easier"""
    # Get login database
    logins = database.load(app.root_path / "records" / "login.json")

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
    """Get username from cookie data

    If cookie data is invalid return None"""
    # Get login database
    logins = database.load(app.root_path / "records" / "login.json")

    # Attempt to get entry for code. Using get instead of
    # "in" search and then index means is faster
    entry = logins.get(code, None)
    # If not exists or malformed entry, is bad
    if entry is None or not isinstance(entry, dict):
        return None
    # If expires not exist in entry or time expired, is bad and delete entry
    if entry.get("expires", -math.inf) < int(time.time()):
        log(f"Login UUID {code!r} expired")
        del logins[code]
        logins.write_file()
        return None
    # Otherwise attempt to return username field or is bad because malformed
    return entry.get("user", None)


def create_uninitialized_account(
    username: str, type_: str | None = None
) -> None:
    """Create uninitialized account. If type is None do not set."""
    users = database.load(app.root_path / "records" / "users.json")
    if username in users:
        error = f"Attempted to create new account for {username} which exists"
        warnings.warn(error)
        log(error, 2)
        return
    users[username] = {
        "status": "not_created",
    }
    if type_ is not None:
        users[username]["type"] = type_
    users.write_file()
    log(f"Created uninitialized account {username!r}")


def add_tickets_to_user(username: str, count: int) -> None:
    """Add ticket count to username. Create account if it doesn't exist."""
    assert count > 0, f"Use subtract_user_tickets instead of adding {count}"

    users = database.load(app.root_path / "records" / "users.json")

    if username not in users:
        create_uninitialized_account(username)
    assert username in users, "Create uninitialized should have made account!"
    users[username]["tickets"] = users[username].get("tickets", 0) + count
    users.write_file()
    log(f"User {username!r} recieved {count!r} tickets")


def get_user_ticket_count(username: str) -> int:
    """Get number of tickets user has at this time

    Raises LookupError if username does not exist"""
    users = database.load(app.root_path / "records" / "users.json")

    if username not in users:
        raise LookupError(f"User {username!r} does not exist")

    count = users[username].get("tickets", 0)
    assert isinstance(count, int)

    return count


def subtract_user_tickets(username: str, count: int) -> int:
    """Remove tickets from user. Return number of tickets left.

    Raises LookupError if username does not exist
    Raises ValueError if count is greater than number of tickets in account"""
    assert count > 0, f"Use add_user_tickets instead of subtracting {count}"

    users = database.load(app.root_path / "records" / "users.json")

    if username not in users:
        raise LookupError(f"User {username!r} does not exist")

    current_tickets = users[username].get("tickets", 0)

    assert isinstance(current_tickets, int)
    new = current_tickets - count

    if new < 0:
        raise ValueError(
            f"Insufficiant tickets for user {username!r} to subtract {count}"
        )
    users[username]["tickets"] = new
    return new


async def convert_joining(code: str) -> bool:
    """Convert joining record to student record"""
    # Get usernames with matching join code and who are joining
    users = database.load(app.root_path / "records" / "users.json")
    usernames = get_user_by(join_code=code, status="joining")
    if len(usernames) != 1:
        log(f"Invalid code {code!r}")
        return False
    username = usernames.pop()

    # If expired, erase and continue
    now = int(time.time())
    expires = users[username].get("join_code_expires", math.inf)

    del users[username]["join_code"]
    del users[username]["join_code_expires"]

    if now > expires:
        users.write_file()

        delta = elapsed.get_elapsed(now - expires)
        log(f"{username!r} join code expired by {delta}")
        return False

    users[username]["status"] = "created"
    users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    log(f"User {username!r} logged in from join code")

    return True


# @app.get("/signup")
# async def signup_get() -> str | wkresp:
#    """Handle sign up get including code register"""
#    # Get code from request arguments if it exists
#    code = request.args.get("code", None)
#    if code is not None:
#        success = await convert_joining(code)
#        if success:
#            return app.redirect("/")
#        return app.redirect("/signup#codeinvalid")
#    return await stream_template(
#        "signup_get.html.jinja",
#    )


# @app.post("/signup")
# async def signup_post() -> wkresp | str:
#    """Handle sign up form"""
#    multi_dict = await request.form
#    response = multi_dict.to_dict()
#
#    # Validate response
#    username = response.get("username", "")
#    password = response.get("password", "")
#
#    if bool(set(username) - set("0123456789")) or len(username) != 6:
#        return app.redirect("/signup#badusername")
#    if len(set(password)) < 7:
#        return app.redirect("/signup#badpassword")
#
#    users = database.load(app.root_path / "records" / "users.json")
#
#    create_link = True
#
#    if username in users:
#        status = users[username].get("status", "not_created")
#        if status == "created":
#            return app.redirect("/signup#userexists")
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
#        log(f"User {username!r} signed up")
#
#    return await stream_template(
#        "signup_post.html.jinja",
#        email=email,
#    )


@app.get("/login")
async def login_get() -> AsyncIterator[str]:
    """Get login page"""
    return await stream_template(
        "login_get.html.jinja",
    )


@app.post("/login")
async def login_post() -> wkresp:
    """Handle login form"""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return app.redirect("/login#bad")

    # Check Credentials here, e.g. username & password.
    users = database.load(app.root_path / "records" / "users.json")

    if username not in users:
        return app.redirect("/login#bad")

    if users[username].get("type", "student") == "student":
        return app.redirect("/login#no-student-login")

    database_value = users[username].get("password", None)
    if database_value is None:
        return app.redirect("/login#bad")
    if not await security.compare_hash(password, database_value, PEPPER):
        # Bad password
        return app.redirect("/login#badpass")

    # Make sure to change status of auto password accounts
    if users[username].get("status") == "created_auto_password":
        users[username]["status"] = "created"
        users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    log(f"User {username!r} logged in")

    return app.redirect("/")


@app.get("/logout")
async def logout() -> wkresp:
    """Handle logout"""
    if await current_user.is_authenticated:
        code = current_user.auth_id
        assert code is not None
        username = get_login_from_cookie_data(code)
        if username is not None:
            log(f"User {username!r} ({code}) logged out")
        else:
            log(f"Invalid UUID {code} logged out", 2)
    logout_user()
    return app.redirect("login")


# Remove this later, potential security vulnerability
@app.get("/user_data")
@login_required
async def user_data_route() -> wkresp | Response:
    """Dump user data"""
    assert current_user.auth_id is not None
    users = database.load(app.root_path / "records" / "users.json")
    username = get_login_from_cookie_data(current_user.auth_id)

    if username is None or username not in users:
        log(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
            2,
        )
        logout_user()
        return app.redirect("login")
    user = users[username] | {"username": username}
    log(f"Record dump for {username!r}", level=0)
    return Response(
        json.dumps(user, sort_keys=True),
        content_type="application/json",
    )


@app.get("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager"})
async def add_tickets_get() -> AsyncIterator[str]:
    """Add tickets page for teachers"""
    return await stream_template(
        "add_tickets_get.html.jinja",
    )


@app.post("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager"})
async def add_tickets_post() -> AsyncIterator[str] | wkresp:
    """Handle post for add tickets form"""
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
        return app.redirect("/add-tickets#badcount")

    add_tickets_to_user(student_id, ticket_count)

    plural = "" if ticket_count < 2 else "s"
    return await stream_template(
        "add_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        student_id=student_id,
    )


@app.get("/subtract-tickets")
@pretty_exception
@login_require_only(type_="manager")
async def subtract_tickets_get() -> AsyncIterator[str]:
    """Subtract tickets page for managers"""
    return await stream_template(
        "subtract_tickets_get.html.jinja",
    )


@app.post("/subtract-tickets")
@pretty_exception
@login_require_only(type_="manager")
async def subtract_tickets_post() -> AsyncIterator[str] | wkresp:
    """Handle post for subtract tickets form"""
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
        return app.redirect("/subtract-tickets#badcount")

    try:
        tickets_left = subtract_user_tickets(student_id, ticket_count)
    except LookupError:
        # Username not exist
        return app.redirect("/subtract-tickets#student-not-found")
    except ValueError:
        # Count > number of tickets in account
        return app.redirect("/subtract-tickets#not-enough-tickets")

    plural = "" if ticket_count < 2 else "s"
    return await stream_template(
        "subtract_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        student_id=student_id,
        tickets_left=tickets_left,
    )


@app.get("/settings")
@pretty_exception
@login_required
async def settings_get() -> AsyncIterator[str]:
    """Settings page get request"""
    return await stream_template(
        "settings_get.html.jinja",
    )


@app.get("/settings/change-password")
@pretty_exception
@login_required
async def settings_change_password_get() -> AsyncIterator[str]:
    """Setting page for password change get"""
    return await stream_template(
        "settings_change_password_get.html.jinja",
    )


@app.post("/settings/change-password")
@pretty_exception
@login_required
async def settings_password_post() -> AsyncIterator[str] | wkresp:
    """Handle password change form"""
    assert current_user.auth_id is not None
    users = database.load(app.root_path / "records" / "users.json")
    username = get_login_from_cookie_data(current_user.auth_id)

    if username is None or username not in users:
        log(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
            2,
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    current_password = response.get("current_password", "")
    new_password = response.get("new_password", "")

    if not current_password or not new_password:
        return app.redirect("/settings/change-password#bad")

    # Check Credentials here, e.g. username & password.
    users = database.load(app.root_path / "records" / "users.json")

    if username not in users:
        return app.redirect("/logout")

    if not await security.compare_hash(
        current_password, users[username]["password"], PEPPER
    ):
        # Bad password
        log(f"{username!r} did not enter own password in change password")
        return app.redirect("/settings/change-password#current_not_match")

    users[username]["password"] = security.create_new_login_credentials(
        new_password, PEPPER
    )
    users.write_file()
    log(f"{username!r} changed their password")

    return await stream_template(
        "settings_change_password_post.html.jinja",
    )


@app.get("/invite-teacher")
@pretty_exception
@login_require_only(type_={"teacher", "manager"})
async def invite_teacher_get() -> AsyncIterator[str]:
    """Create new teacher account"""
    return await stream_template(
        "invite_teacher_get.html.jinja",
    )


@app.post("/invite-teacher")
@pretty_exception
@login_require_only(type_={"teacher", "manager"})
async def invite_teacher_post() -> AsyncIterator[str] | wkresp:
    """Invite teacher form post handling"""
    assert current_user.auth_id is not None
    users = database.load(app.root_path / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        log(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
            2,
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return app.redirect("/invite-teacher#badusername")
    length = len(new_account_username)
    if length < 3 or length > 16:
        return app.redirect("/invite-manager#badusername")

    possible_name = set("abcdefghijklmnopqrstuvwxyz0123456789")
    if bool(set(new_account_username) - possible_name):
        return app.redirect("/invite-teacher#badusername")

    users = database.load(app.root_path / "records" / "users.json")

    if new_account_username in users:
        if users[new_account_username]["status"] != "created_auto_password":
            return app.redirect("/invite-teacher#userexists")

    password = secrets.token_urlsafe(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "teacher",
        "status": "created_auto_password",
    }

    users.write_file()

    log(f"{creator_username!r} invited {new_account_username!r} as teacher")

    return await stream_template(
        "invite_teacher_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


@app.get("/invite-manager")
@pretty_exception
@login_require_only(type_="manager")
async def invite_manager_get() -> AsyncIterator[str]:
    """Create a new manager account"""
    return await stream_template(
        "invite_manager_get.html.jinja",
    )


@app.post("/invite-manager")
@pretty_exception
@login_require_only(type_="manager")
async def invite_manager_post() -> AsyncIterator[str] | wkresp:
    """Invite manager form post handling"""
    assert current_user.auth_id is not None
    users = database.load(app.root_path / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        log(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
            2,
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return app.redirect("/invite-manager#badusername")
    length = len(new_account_username)
    if length < 3 or length > 16:
        return app.redirect("/invite-manager#badusername")

    possible_name = set("abcdefghijklmnopqrstuvwxyz0123456789")
    if bool(set(new_account_username) - possible_name):
        return app.redirect("/invite-manager#badusername")

    users = database.load(app.root_path / "records" / "users.json")

    if new_account_username in users:
        if users[new_account_username]["status"] != "created_auto_password":
            return app.redirect("/invite-manager#userexists")

    password = secrets.token_urlsafe(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "manager",
        "status": "created_auto_password",
    }

    users.write_file()

    log(f"{creator_username!r} invited {new_account_username!r} as manager")

    return await stream_template(
        "invite_manager_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


async def ticket_get_form() -> AsyncIterator[str]:
    """Generate form for ticket GET when no ID given"""
    return await stream_template(
        "ticket_get_form.html.jinja",
    )


async def ticket_count_page(username: str) -> AsyncIterator[str]:
    """Ticket count page for given username"""
    try:
        count = get_user_ticket_count(username)
    except LookupError:
        count = 0

    user_link = app.url_for("tickets_get") + "?" + urlencode({"id": username})

    return await stream_template(
        "ticket_count.html.jinja",
        username=repr(username),
        count=repr(count),
        user_link=user_link,
    )


@app.get("/tickets")
@pretty_exception
async def tickets_get() -> AsyncIterator[str] | wkresp:
    """Tickets view page"""
    # Get username from request arguments if it exists
    username = request.args.get("id", None)

    if not username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")):
        # If username has any character except 0-9, bad
        return await ticket_get_form()

    return await ticket_count_page(username)


@app.post("/tickets")
@pretty_exception
async def tickets_post() -> AsyncIterator[str] | wkresp:
    """Invite teacher form post handling"""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    username = response.get("student_id", None)

    if username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")):
        # If username has any character except 0-9, bad
        return await ticket_get_form()

    return await ticket_count_page(username)


@app.get("/")
async def root_get() -> AsyncIterator[str] | wkresp:
    """Main page GET request"""

    user_name = ""
    user_type = ""
    if await current_user.is_authenticated:
        users = database.load(app.root_path / "records" / "users.json")
        assert current_user.auth_id is not None
        loaded_user = get_login_from_cookie_data(current_user.auth_id)

        if loaded_user is None or loaded_user not in users:
            log(
                f"Invalid login UUID {current_user.auth_id} "
                "in authenticated user",
                2,
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


async def run_async(
    root_dir: str,
    port: int,
    *,
    ip_addr: str | None = None,
    cookie_secret: str | None = None,
) -> None:
    """Asynchronous Entry Point"""
    if ip_addr is None:
        ip_addr = find_ip()

    try:
        # Add more information about the address
        location = f"{ip_addr}:{port}"

        config = {
            "bind": [location],
            "worker_class": "trio",
            "errorlog": path.join(
                root_dir, "logs", time.strftime("log_%Y_%m_%d.log")
            ),
        }
        if DOMAIN:
            config[
                "certfile"
            ] = f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
            config["keyfile"] = f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem"
        else:
            app.config["QUART_AUTH_COOKIE_SECURE"] = False
        app.config["QUART_AUTH_COOKIE_SAMESITE"] = "Strict"
        app.config["SERVER_NAME"] = location

        app.static_folder = Path(root_dir, "static")

        app.add_url_rule(
            "/",
            "static",
            app.send_static_file,
            defaults={"filename": "index.html"},
        )
        app.add_url_rule("/<path:filename>", "static", app.send_static_file)
        app.secret_key = cookie_secret

        config_obj = Config.from_mapping(config)

        proto = "http" if not DOMAIN else "https"
        print(f"Serving on {proto}://{location}\n(CTRL + C to quit)")

        await serve(app, config_obj)
    except socket.error:
        log(f"Cannot bind to IP address '{ip_addr}' port {port}", 2)
        sys.exit(1)
    except KeyboardInterrupt:
        log("Shutting down from keyboard interrupt")


def run() -> None:
    """Synchronous Entry Point"""
    root_dir = path.dirname(__file__)
    port = 6002

    cookie_secret: Final = getenv("COOKIE_SECRET")

    if cookie_secret is None:
        print(
            """\nNo token set!
Either add ".env" file in bots folder with COOKIE_SECRET=<token here> line,
or set COOKIE_SECRET environment variable."""
        )
        return

    trio.run(
        functools.partial(
            run_async, root_dir, port, cookie_secret=cookie_secret
        )
    )


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    try:
        run()
    finally:
        database.unload_all()
