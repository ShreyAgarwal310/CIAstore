#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Server - Caught In the Act Server

"Caught In the Act Server"


__title__ = "Caught In the Act Server"
__author__ = "CSHS Members"
__version__ = "0.0.0"


from typing import Final
from os import path, getenv
import sys
import socket
from pathlib import Path
from urllib.parse import urlencode
import time
import json
from functools import partial
import uuid

import trio
from dotenv import load_dotenv
from hypercorn.config import Config
from hypercorn.trio import serve
from quart_trio import QuartTrio
from quart import request, Response, render_template_string
from quart_auth import (
    AuthManager,
    AuthUser,
    Action,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug import Response as wkresp

from ciastore import htmlgen, security, database


load_dotenv()
DOMAIN: Final = None
PEPPER: Final = getenv("COOKIE_SECRET", "")


def log(message: str, level: int = 0, log_dir: str | None = None) -> None:
    "Log a message to console and log file."
    levels = ["INFO", "ERROR"]

    if log_dir is None:
        log_dir = path.dirname(__file__)
    log_file = path.join(log_dir, "log.txt")

    log_level = levels[min(max(0, level), len(levels) - 1)]
    log_time = time.asctime()
    log_message_text = message.encode("unicode_escape").decode("utf-8")

    log_msg = f"[{__title__}] [{log_time}] [{log_level}] {log_message_text}"

    if not path.exists(log_file):
        with open(log_file, mode="w", encoding="utf-8") as file:
            file.close()
        log("Log file does not exist!", 1)
        log("Created log file")
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


##class User(AuthUser):
##    def __init__(self, auth_id: str | None) -> None:
##        super().__init__(auth_id)
##        self.action = Action.WRITE

app: Final = QuartTrio(__name__)
AuthManager(app)


##@app.get('/')
##async def root_GET() -> str:
##    "Main page GET request"
##    msg = "If you're reading this, the web server was installed correctly.™"
##    value = htmlgen.wrap_tag('i', msg, False)
##    html = htmlgen.contain_in_box('', value)
##    return htmlgen.get_template('CompanyName.website', html)


class Student(AuthUser):
    """Student class"""

    __slots__ = ("data",)

    def __init__(self, data: dict[str, str]) -> None:
        self.data = data

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.data!r})"


async def convert_joining(code: str) -> wkresp:
    students = database.load(app.root_path / "records" / "students.json")
    joining = database.load(app.root_path / "records" / "joining.json")

    user = joining[code]

    del joining[code]
    joining.write_file()

    students[user["username"]] = {"password": user["password"], "email": user["email"]}
    students.write_file()

    user = AuthUser(user["username"])
    login_user(user)

    return app.redirect("/restricted")


@app.get("/signup")
async def signup_GET() -> str | wkresp:
    code = request.args.get("code", None)
    if code is not None:
        joining = database.load(app.root_path / "records" / "joining.json")
        if code in joining:
            return await convert_joining(code)

    fields = []
    fields.append(htmlgen.field_select("username", "Username:"))
    fields.append(htmlgen.field_select("password", "Password:", field_type="password"))
    contents = "<br>\n".join(fields)
    form = htmlgen.get_form("signup", contents, "Sign up", "Sign up")
    body = htmlgen.contain_in_box(form)
    return htmlgen.get_template("Sign up", body)


@app.post("/signup")
async def signup_POST() -> wkresp:
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return app.redirect("/signup#bad")
    if bool(set(username) - set("0123456789")) or len(username) != 6:
        return app.redirect("/signup#bad")
    if len(password) < 15 or len(set(password)) < 4:
        return app.redirect("/signup#badpass")

    students = database.load(app.root_path / "records" / "students.json")
    joining = database.load(app.root_path / "records" / "joining.json")

    if username in students:
        return app.redirect("/signup#userexists")

    # Email people
    email = f"{username}@class.lps.org"
    while (code := str(uuid.uuid4())) in joining:
        continue
    link = app.url_for("signup_GET", _external=True) + "?" + urlencode({"code": code})
    print(f"{link = }")
    # TODO: Message email code

    joining[code] = {
        "username": username,
        "password": security.create_new_login_credentials(password, PEPPER),
        "email": email,
    }
    joining.write_file()

    text = f"Sent an email to {email} containing your a link to verify your account."
    body = htmlgen.wrap_tag("p", text, False)
    return htmlgen.get_template("Check your email", body)


@app.get("/login")
async def login_GET() -> str:
    fields = []
    fields.append(htmlgen.field_select("username", "Username:"))
    fields.append(htmlgen.field_select("password", "Password:", field_type="password"))
    contents = "<br>\n".join(fields)

    form = htmlgen.get_form("login", contents, "Sign In", "Login")
    parts = []
    parts.append(htmlgen.contain_in_box(form))
    parts.append(htmlgen.create_link("/signup", "Don't have an account?"))
    ##    parts.append(htmlgen.create_link('/forgot', "Forgot password?"))
    body = "<br>\n".join(parts)
    return htmlgen.get_template("Login", body)


@app.post("/login")
async def login_POST() -> wkresp:
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return app.redirect("/login#bad")

    # Check Credentials here, e.g. username & password.
    students = database.load(app.root_path / "records" / "students.json")

    if not username in students:
        return app.redirect("/login#bad")

    database_value = students[username]["password"]
    if not await security.compare_hash(password, database_value, PEPPER):
        # Bad password
        return app.redirect("/login#badpass")

    user = AuthUser(username)
    login_user(user)
    log(f"User {user!r} logged in")

    return app.redirect("restricted")


@app.get("/logout")
async def logout() -> wkresp:
    if current_user.is_authenticated:
        log(f"User {current_user.auth_id!r} logged out")
    logout_user()
    return app.redirect("login")


@app.get("/restricted")
@login_required
async def restricted_route() -> str:
    students = database.load(app.root_path / "records" / "students.json")
    if not current_user.auth_id in students:
        return app.redirect("/logout")
    student = students[current_user.auth_id]
    return json.dumps(student)


##@app.get("/hello")
##async def hello() -> str:
##    print(current_user.auth_id)
##    return await render_template_string(
##        """
##    {% if current_user.is_authenticated %}
##      Hello logged in user
##    {% else %}
##      Hello logged out user
##    {% endif %}
##    """
##    )


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
            "errorlog": path.join(root_dir, "log.txt"),
        }
        if DOMAIN:
            config["certfile"] = "/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
            config["keyfile"] = "/etc/letsencrypt/live/{DOMAIN}/privkey.pem"
        app.config["QUART_AUTH_COOKIE_SAMESITE"] = "Strict"
        app.config["QUART_AUTH_COOKIE_SECURE"] = False
        app.config["SERVER_NAME"] = location

        app.static_folder = Path(root_dir, "static")

        app.add_url_rule(
            "/", "static", app.send_static_file, defaults={"filename": "index.html"}
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
    run()
