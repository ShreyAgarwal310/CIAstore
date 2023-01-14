#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Server - Caught In the Act Server

"Caught In the Act Server"


__title__ = "Caught In the Act Server"
__author__ = "CSHS Members"
__version__ = "0.0.0"


import json
import socket
import sys
import time
import uuid
from functools import partial
from os import getenv, makedirs, path
from pathlib import Path
from typing import Final
from urllib.parse import urlencode

import trio
from dotenv import load_dotenv
from hypercorn.config import Config
from hypercorn.trio import serve
from quart import Response, request
from quart_auth import (AuthManager, AuthUser, current_user, login_required,
                        login_user, logout_user)
from quart_trio import QuartTrio
from werkzeug import Response as wkresp

from ciastore import database, htmlgen, security

load_dotenv()
DOMAIN: str | None = None
PEPPER: Final = getenv("COOKIE_SECRET", "")


def log(message: str, level: int = 0, log_dir: str | None = None) -> None:
    "Log a message to console and log file."
    levels = ["INFO", "ERROR"]

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


def template(
    title: str,
    body: str,
    *,
    head: str = "",
    body_tag: dict[str, htmlgen.TagArg] | None = None,
    lang: str = "en",
) -> str:
    """HTML Template for application"""
    head_data = "\n".join(
        (
            htmlgen.wrap_tag(
                "style",
                "\n".join(
                    (
                        htmlgen.css("*", font_family="Lucida Console"),
                        htmlgen.css(("h1", "footer"), text_align="center"),
                        htmlgen.css(("html", "body"), height="100%"),
                        htmlgen.css(
                            "body", display="flex", flex_direction="column"
                        ),
                        htmlgen.css(".content", flex=(1, 0, "auto")),
                        htmlgen.css(
                            ".footer",
                            flex_shrink=0,
                        ),
                    )
                ),
            ),
            head,
        )
    )

    body_data = "\n".join(
        (
            htmlgen.wrap_tag(
                "div",
                "\n".join(
                    (
                        htmlgen.wrap_tag("h1", "Caught In the Act", False),
                        htmlgen.wrap_tag("h2", title, False),
                        body,
                    )
                ),
                class_="content",
            ),
            htmlgen.wrap_tag(
                "footer",
                "\n".join(
                    (
                        htmlgen.wrap_tag(
                            "i",
                            "If you're reading this, the web server "
                            "was installed correctly.™",
                            block=False,
                        ),
                        htmlgen.tag("hr"),
                        htmlgen.wrap_tag(
                            "p", f"{__title__} v{__version__} © {__author__}"
                        ),
                    )
                ),
            ),
        )
    )

    return htmlgen.template(
        title, body_data, head=head_data, body_tag=body_tag
    )


app: Final = QuartTrio(__name__)
AuthManager(app)


def get_user_by(**kwargs: str) -> set[str]:
    """Get set of usernames of given type"""
    users = database.load(app.root_path / "records" / "users.json")
    table = users.table("username")
    usernames: tuple[str, ...] = table["username"]

    result: set[str] = set(usernames)

    for key, value in kwargs.items():
        sub_result: set[str] = set()
        for index, entry_type in enumerate(table[key]):
            if entry_type == value:
                sub_result.add(usernames[index])
        result &= sub_result
    return result


async def convert_joining(code: str) -> bool:
    """Convert joining record to student record"""
    # Get usernames with matching join code and who are joining
    users = database.load(app.root_path / "records" / "users.json")
    usernames = get_user_by(join_code=code, status="joining")
    if len(usernames) != 1:
        return False
    username = usernames.pop()

    users[username]["join_code"] = None
    users[username]["status"] = "created"
    users.write_file()

    user = AuthUser(username)
    login_user(user)

    return True


@app.get("/signup")
async def signup_get() -> str | wkresp:
    """Handle sign up get including code register"""
    # Get code from request arguments if it exists
    code = request.args.get("code", None)
    if code is not None:
        success = await convert_joining(code)
        if success:
            return app.redirect("/")

    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "username",
                "Username:",
                attrs={"placeholder": "Your LPS ID"},
            ),
            htmlgen.input_field(
                "password",
                "Password:",
                field_type="password",
                attrs={"placeholder": "Password that meets criteria"},
            ),
        )
    )
    form = htmlgen.form("signup", contents, "Sign up", "Sign up")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(
                "<br>\n".join(
                    (
                        form,
                        htmlgen.wrap_tag(
                            "i",
                            "Password at least 15 characters long and "
                            "at least 4 different characters",
                        ),
                    )
                )
            ),
            htmlgen.create_link("/login", "Already have an account?"),
        )
    )
    return template("Sign up", body)


@app.post("/signup")
async def signup_post() -> wkresp | str:
    """Handle sign up form"""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return app.redirect("/signup#bad")
    if bool(set(username) - set("0123456789")) or len(username) != 6:
        return app.redirect("/signup#badusername")
    if len(password) < 15 or len(set(password)) < 4:
        return app.redirect("/signup#badpass")

    users = database.load(app.root_path / "records" / "users.json")

    if username in users and users[username].get("status") != "not_created":
        return app.redirect("/signup#userexists")

    # Email people
    email = f"{username}@class.lps.org"

    # If not already in joining list, add and send code
    if username not in get_user_by(status="joining"):
        table = users.table("username")
        existing_codes = table["join_code"]
        while (code := str(uuid.uuid4())) in existing_codes:
            continue
        link = (
            app.url_for("signup_get", _external=True)
            + "?"
            + urlencode({"code": code})
        )
        print(f"{link = }")
        # TODO: Message email code

        if username not in users:
            users[username] = {}

        users[username].update(
            {
                "password": security.create_new_login_credentials(
                    password, PEPPER
                ),
                "email": users[username].get("email", email),
                "type": users[username].get("type", "student"),
                "status": "joining",
                "join_code": code,
            }
        )
        users.write_file()

    text = (
        f"Sent an email to {email} containing "
        + "your a link to verify your account."
    )
    body = htmlgen.wrap_tag("p", text, False)
    return template("Check your email", body)


@app.get("/login")
async def login_get() -> str:
    """Get login page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "username",
                "Username:",
                attrs={"placeholder": "Username"},
            ),
            htmlgen.input_field(
                "password",
                "Password:",
                field_type="password",
                attrs={"placeholder": "Password"},
            ),
        )
    )

    form = htmlgen.form("login", contents, "Sign In", "Login")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.create_link("/signup", "Don't have an account?"),
            # htmlgen.create_link('/forgot', "Forgot password?"),
        )
    )
    return template("Login", body)


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

    database_value = users[username]["password"]
    if not await security.compare_hash(password, database_value, PEPPER):
        # Bad password
        return app.redirect("/login#badpass")

    user = AuthUser(username)
    login_user(user)
    log(f"User {username!r} logged in")

    return app.redirect("/")


@app.get("/logout")
async def logout() -> wkresp:
    """Handle logout"""
    if await current_user.is_authenticated:
        log(f"User {current_user.auth_id!r} logged out")
    logout_user()
    return app.redirect("login")


@app.get("/user_data")
@login_required
async def user_data_route() -> wkresp | Response:
    """Dump user data"""
    assert current_user.auth_id is not None
    users = database.load(app.root_path / "records" / "users.json")
    if current_user.auth_id not in users:
        return app.redirect("/logout")
    user = users[current_user.auth_id].copy()
    user["username"] = current_user.auth_id
    return Response(
        json.dumps(user, sort_keys=True),
        content_type="application/json",
    )


@app.get("/")
async def root_get() -> str:
    """Main page GET request"""

    if await current_user.is_authenticated:
        status = f"Hello logged in user {current_user.auth_id}."
        links = {
            "View user data": "/user_data",
            "Log Out": "/logout",
        }
    else:
        login_url = app.url_for("login_get", _external=True)
        login_link = htmlgen.create_link(login_url, "this link")
        status = f"Please log in at {login_link}."
        links = {
            "Log In": "/login",
            "Sign Up": "/signup",
        }
    link_block = htmlgen.bullet_list(
        [htmlgen.create_link(ref, disp) for disp, ref in links.items()]
    )
    login_msg = htmlgen.wrap_tag("p", status)
    body = "\n".join(
        (
            htmlgen.contain_in_box(login_msg),
            htmlgen.wrap_tag("p", "Links:"),
            link_block,
        )
    )
    return template("Caught In the Act", body)


@app.get("/settings")
async def settings_get() -> str:
    """Settings page get request"""
    return template("settings", "TODO settings page")


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
            config["certfile"] = "/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
            config["keyfile"] = "/etc/letsencrypt/live/{DOMAIN}/privkey.pem"
        app.config["QUART_AUTH_COOKIE_SAMESITE"] = "Strict"
        app.config["QUART_AUTH_COOKIE_SECURE"] = False
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
        log(f"Cannot bind to IP address '{ip_addr}' port {port}", 1)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


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

    trio.run(partial(run_async, root_dir, port, cookie_secret=cookie_secret))


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    try:
        run()
    finally:
        database.unload_all()
