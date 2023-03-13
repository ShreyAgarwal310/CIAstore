"Generate pages for the caught in the act store"

# Programmed by CoolCat467

__title__ = "Generate Pages"
__author__ = "CoolCat467"


import pathlib
from typing import Callable, Final

from ciastore import htmlgen, server

TEMPLATE_FOLDER: Final = pathlib.Path("templates")
TEMPLATE_FUNCTIONS: dict[str, Callable[[], str]] = {}
STATIC_FOLDER: Final = pathlib.Path("static")
STATIC_FUNCTIONS: dict[str, Callable[[], str]] = {}


def save_template(name: str, content: str) -> None:
    """Save content as new template "{name}" """
    assert TEMPLATE_FOLDER is not None
    template_path = TEMPLATE_FOLDER / f"{name}.html.jinja"
    with open(template_path, "w", encoding="utf-8") as template_file:
        template_file.write(content)
    print(f"Saved content to {template_path}")


def save_static(filename: str, content: str) -> None:
    """Save content as new static file "{filename}" """
    assert STATIC_FOLDER is not None
    static_path = STATIC_FOLDER / filename
    with open(static_path, "w", encoding="utf-8") as static_file:
        static_file.write(content)
    print(f"Saved content to {static_path}")


def save_template_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated template as filename"""

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if filename in TEMPLATE_FUNCTIONS:
            raise NameError(
                f"{filename!r} already exists as template filename"
            )
        TEMPLATE_FUNCTIONS[filename] = function
        return function

    return function_wrapper


def save_static_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated static file as filename"""

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if filename in STATIC_FUNCTIONS:
            raise NameError(f"{filename!r} already exists as static filename")
        STATIC_FUNCTIONS[filename] = function
        return function

    return function_wrapper


@save_static_as("style.css")
def generate_style_css() -> str:
    """Generate style.css static file"""
    mono = "SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace"
    return "\n".join(
        (
            htmlgen.css(
                "@font-face",
                font_family="Nunito Sans",
                src="NunitoSans-Regular.ttf",
            ),
            htmlgen.css(
                "@font-face",
                font_family="Tilt Warp",
                src="TiltWarp-Regular.ttf",
            ),
            htmlgen.css(
                ("*", "*::before", "*::after"),
                box_sizing="border-box",
                margin=0,
                # font_family="Lucida Console",
                font_family="Nunito Sans",
            ),
            htmlgen.css(("h1", "footer"), text_align="center"),
            htmlgen.css(
                "h1",
                font_family="Tilt Warp",
                color="#152287",
            ),
            htmlgen.css(("html", "body"), height="100%"),
            htmlgen.css(
                "body",
                line_height=1.5,
                _webkit_font_smoothing="antialiased",
                display="flex",
                flex_direction="column",
                background_color="#6bdaff",
                align_items="center",
                justify_content="center",
                # overflow="hidden",
            ),
            htmlgen.css(".content", flex=(1, 0, "auto")),
            htmlgen.css(
                ".footer",
                flex_shrink=0,
            ),
            htmlgen.css(
                ("img", "picture", "video", "canvas", "svg"),
                display="block",
                max_width="100%",
            ),
            htmlgen.css(
                ("input", "button", "textarea", "select"),
                font="inherit",
            ),
            htmlgen.css(
                ("p", "h1", "h2", "h3", "h4", "h5", "h6"),
                overflow_wrap="break-word",
            ),
            htmlgen.css(
                ("#root", "#__next"),
                isolation="isolate",
            ),
            htmlgen.css(
                "code",
                padding=("0.2em", "0.4em"),
                background_color="rgba(158,167,179,0.4)",
                border_radius="6px",
                font_family=mono,
                line_height=1.5,
            ),
            htmlgen.css(
                "::placeholder",
                font_style="italic",
            ),
            htmlgen.css(
                "div:not(.content)",
                background_color="white",
                padding_left="2%",
                padding_right="2%",
                padding_bottom="2%",
                border_radius="8px",
                border=("2px", "solid", "#ebebeb"),
                margin="4px",
                text_align="justify",
            ),
            htmlgen.css(
                "label",
                margin_top="2%",
                display="block",
            ),
            htmlgen.css(
                "input",
                width="100%",
            ),
            htmlgen.css(
                "#noticeText",
                font_size="10px",
                display="inline-block",
                white_space="nowrap",
            ),
            htmlgen.css(
                'input[type="submit"]',
                background_color="#152287",
                color="#ffffff",
                border=("2px", "solid", "black"),
                border_radius="4px",
                margin_top="8%",
                min_width="min-content",
                height="20%",
            ),
            htmlgen.css(
                'input[type="submit"]:hover',
                background_color="#152287b0",
            ),
            htmlgen.css_block(
                "@media screen and (max-width: 480px)",
                htmlgen.css(
                    "div:not(.content)",
                    min_width="75%",
                    padding_bottom="5%",
                ),
            ),
        )
    )


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
            htmlgen.tag(
                "link", rel="stylesheet", type_="text/css", href="/style.css"
            ),
            head,
        )
    )

    join_body = (
        htmlgen.wrap_tag("h1", title, False),
        body,
    )

    footer = f"{server.__title__} v{server.__version__} © {server.__author__}"

    body_data = "\n".join(
        (
            htmlgen.wrap_tag(
                "div",
                "\n".join(join_body),
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
                            "p",
                            footer,
                        ),
                    )
                ),
            ),
        )
    )

    return htmlgen.template(
        title, body_data, head=head_data, body_tag=body_tag, lang=lang
    )


@save_template_as("signup_get")
def generate_signup_get() -> str:
    """Generate /signup get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "username",
                "Username:",
                attrs={
                    "placeholder": "Your LPS ID",
                    "autofocus": "",
                    "required": "",
                },
            ),
            htmlgen.input_field(
                "password",
                "Password:",
                field_type="password",
                attrs={
                    "placeholder": "Secure password",
                    "required": "",
                },
            ),
        )
    )

    form = htmlgen.form("signup", contents, "Sign up")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.wrap_tag(
                "i",
                "Password needs at least 7 different characters",
                block=False,
            ),
            htmlgen.link_list(
                {
                    "/login": "Already have an account?",
                }
            ),
        )
    )
    return template("Sign up", body)


@save_template_as("signup_post")
def generate_signup_post() -> str:
    """Generate /signup post page"""
    text = (
        "Sent an email to {{ email }} containing "
        + "your a link to verify your account."
    )
    body = htmlgen.wrap_tag("p", text, False)
    return template("Check your email", body)


@save_template_as("login_get")
def generate_login_get() -> str:
    """Generate /login get page"""
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

    form = htmlgen.form("login", contents, "Sign In")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.link_list(
                {
                    "/signup": "Don't have an account?",
                    # "/forgot": "Forgot password?",
                }
            ),
        )
    )
    return template("Login", body)


@save_template_as("add_tickets_get")
def generate_add_tickets_get() -> str:
    """Generate /add-tickets get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "id",
                "Student ID Number",
                field_type="text",
                attrs={
                    "autofocus": "",
                    "required": "",
                    "placeholder": "LPS Student ID",
                    "pattern": "[0-9]{6}",
                },
            ),
            htmlgen.input_field(
                "ticket_count",
                "Number of Tickets",
                field_type="number",
                attrs={
                    "required": "",
                    "value": 1,
                    "min": 1,
                    "max": 10,
                },
            ),
        )
    )
    form = htmlgen.form("add-tickets", contents, "Submit")
    body = htmlgen.contain_in_box(form)
    return template("Add Tickets For Student", body)


@save_template_as("add_tickets_post")
def generate_add_tickets_post() -> str:
    """Generate /add-tickets post page"""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "p",
                    "Added {{ ticket_count }} ticket{{ plural }} "
                    + "for {{ student_id }}",
                    block=False,
                )
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                }
            ),
        )
    )
    return template("Added Tickets", body)


@save_template_as("subtract_tickets_get")
def generate_subtract_tickets_get() -> str:
    """Generate /subtract-tickets get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "id",
                "Student ID Number",
                field_type="text",
                attrs={
                    "autofocus": "",
                    "required": "",
                    "placeholder": "LPS Student ID",
                    "pattern": "[0-9]{6}",
                },
            ),
            htmlgen.input_field(
                "ticket_count",
                "Number of Tickets",
                field_type="number",
                attrs={
                    "required": "",
                    "value": 1,
                    "min": 1,
                    "max": 100,
                },
            ),
        )
    )
    form = htmlgen.form("add-tickets", contents, "Submit")
    body = htmlgen.contain_in_box(form)
    return template("Subtract Tickets From Student", body)


@save_template_as("subtract_tickets_post")
def generate_subtract_tickets_post() -> str:
    """Generate /subtract-tickets post page"""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "p",
                    "Subtracted {{ ticket_count }} ticket{{ plural }} "
                    "from {{ student_id }}. They now have {{ tickets_left }} "
                    "tickets",
                    block=False,
                )
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                }
            ),
        )
    )
    return template("Subtracted Tickets", body)


@save_template_as("settings_get")
def generate_settings_get() -> str:
    """Generate /settings get page"""
    links = {
        "/settings/change-password": "Change Password",
    }
    body = "\n".join(
        (
            htmlgen.link_list(links),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                }
            ),
        )
    )
    return template("User Settings", body)


@save_template_as("settings_change_password_get")
def generate_settings_change_password_get() -> str:
    """Generate /settings/change-password get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "current_password",
                "Current Password:",
                field_type="password",
                attrs={
                    "placeholder": "Your current password",
                    "required": "",
                },
            ),
            htmlgen.input_field(
                "new_password",
                "New Password:",
                field_type="password",
                attrs={
                    "placeholder": "New secure password",
                    "required": "",
                },
            ),
        )
    )
    form = htmlgen.form(
        "change_password",
        contents,
        "Change Password",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "All Account Settings",
                }
            ),
        )
    )
    return template("Change Password", body)


@save_template_as("settings_change_password_post")
def generate_settings_change_password_post() -> str:
    """Generate /settings/change-password post page"""
    body = "\n".join(
        (
            htmlgen.wrap_tag(
                "p", "Password changed successfully", block=False
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "All Account Settings",
                }
            ),
        )
    )
    return template("Password Changed", body)


@save_template_as("invite_teacher_get")
def generate_invite_teacher_get() -> str:
    """Generate /invite-teacher get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "new_account_username",
                "New Account Username (3-16 lowercase characters)",
                attrs={
                    "autofocus": "",
                    "required": "",
                    "placeholder": "LPS Staff Username",
                    "pattern": "[a-z]{3,16}",
                },
            ),
            "",
        )
    )
    form = htmlgen.form(
        "invite-teacher",
        contents,
        "Create New Account",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                }
            ),
        )
    )
    return template("Invite A Teacher", body)


@save_template_as("invite_teacher_post")
def generate_invite_teacher_post() -> str:
    """Generate /invite-teacher post page"""
    body = "\n".join(
        (
            htmlgen.wrap_tag(
                "p",
                "Created new account with login credentials:",
                block=False,
            ),
            htmlgen.contain_in_box(
                "".join(
                    (
                        "Username: ",
                        htmlgen.wrap_tag(
                            "code", "{{ new_account_username }}", block=False
                        ),
                        "\n",
                        htmlgen.tag("br"),
                        "\n",
                        "Password: ",
                        htmlgen.wrap_tag(
                            "code", "{{ password }}", block=False
                        ),
                    )
                )
            ),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "i",
                "Password can be changed in settings later",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "strong",
                "Please write this down, it will not be viewable again!",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                    "/invite-teacher": "Invite Another Teacher",
                }
            ),
        )
    )

    return template("Created New Account!", body)


@save_template_as("invite_manager_get")
def generate_invite_manager_get() -> str:
    """Generate /invite-manager get page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "new_account_username",
                "New Account Username (3-16 lowercase characters)",
                attrs={
                    "autofocus": "",
                    "required": "",
                    "placeholder": "LPS Staff Username",
                    "pattern": "[a-z]{3,16}",
                },
            ),
            "",
        )
    )
    form = htmlgen.form(
        "invite-manager",
        contents,
        "Create New Account",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                }
            ),
        )
    )
    return template("Invite A Manager", body)


@save_template_as("invite_manager_post")
def generate_invite_manager_post() -> str:
    """Generate /invite-manager post page"""
    body = "\n".join(
        (
            htmlgen.wrap_tag(
                "p",
                "Created new account with login credentials:",
                block=False,
            ),
            htmlgen.contain_in_box(
                "".join(
                    (
                        "Username: ",
                        htmlgen.wrap_tag(
                            "code",
                            htmlgen.jinja_expression("new_account_username"),
                            block=False,
                        ),
                        "\n",
                        htmlgen.tag("br"),
                        "\n",
                        "Password: ",
                        htmlgen.wrap_tag(
                            "code",
                            htmlgen.jinja_expression("password"),
                            block=False,
                        ),
                    )
                )
            ),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "i",
                "Password can be changed in settings later",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "strong",
                "Please write this down, it will not be viewable again!",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                    "/invite-teacher": "Invite a Teacher",
                    "/invite-manager": "Invite Another Manager",
                }
            ),
        )
    )

    return template("Created New Account!", body)


@save_template_as("ticket_form")
def generate_ticket_form() -> str:
    """Generate tickets get ticket form page"""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "student_id",
                "Student ID:",
                attrs={
                    "placeholder": "Student ID Number",
                    "autocomplete": "off",
                },
            ),
        )
    )

    form = htmlgen.form(
        "get_student_id",
        contents,
        "Display Tickets",
    )

    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                }
            ),
        )
    )
    return template("Enter ID", body)


@save_template_as("ticket_count_page")
def generate_ticket_count_page() -> str:
    """Generate tickets get ticket count page"""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "h3",
                    "{{ username }} currently has {{ count }} tickets",
                    block=False,
                )
            ),
            htmlgen.create_link("{{ user_link }}", "Link to this user"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/tickets": "Display tickets for user",
                    "/": "Return to main page",
                }
            ),
        )
    )
    return template("Ticket Count", body)


@save_template_as("root_get")
def generate_root_get() -> str:
    """Generate / (root) get page"""
    login_link = htmlgen.create_link("/login", "this link")

    teacher_case = {
        'user_type in ("teacher", "manager")': htmlgen.link_list(
            {
                "/add-tickets": "Add Tickets for Student",
                "/invite-teacher": "Invite Teacher",
            }
        )
    }

    manager_case = {
        'user_type in ("manager")': htmlgen.link_list(
            {
                "/subtract-tickets": "Subtract Tickets for Student",
                "/invite-manager": "Invite Manager",
            }
        )
    }

    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.jinja_if_block(
                    {
                        'user_name == ""': htmlgen.wrap_tag(
                            "p", f"Please log in at {login_link}."
                        ),
                        "": htmlgen.wrap_tag(
                            "p", "Hello logged in user {{ user_name }}."
                        ),
                    }
                )
            ),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.jinja_if_block(
                {
                    'user_name == ""': htmlgen.link_list(
                        {
                            "/login": "Log In",
                            # "/signup": "Sign Up",
                        }
                    ),
                    "": "\n".join(
                        (
                            htmlgen.link_list(
                                {
                                    "/user_data": "[DEBUG] View user data",
                                    "/logout": "Log Out",
                                    "/settings": "Account Settings",
                                    "/tickets": "View ticket count",
                                }
                            ),
                            htmlgen.jinja_if_block(teacher_case),
                            htmlgen.jinja_if_block(manager_case),
                        )
                    ),
                }
            ),
        )
    )
    return template("Caught In the Act", body)


def run() -> None:
    "Generate all page templates and static files"
    for filename, function in TEMPLATE_FUNCTIONS.items():
        save_template(filename, function())
    for filename, function in STATIC_FUNCTIONS.items():
        save_static(filename, function())


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    run()
