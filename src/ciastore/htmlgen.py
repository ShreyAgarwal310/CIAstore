def indent(level: int, text: str) -> str:
    """Indent text by level of spaces."""
    prefix = " " * level
    return "\n".join(prefix + line for line in text.splitlines())


def deindent(level: int, text: str) -> str:
    """Undo indent on text by level of characters."""
    prefix = " " * level
    return "\n".join(line.removeprefix(prefix) for line in text.splitlines())


def get_tag(tag_type: str, args: dict[str, str] | None = None) -> str:
    """Get HTML tag"""
    tag_args = ""
    if args is not None:
        tag_args = " " + " ".join(f'{k}="{v}"' for k, v in args.items())
    return f"<{tag_type}{tag_args}>"


def wrap_tag(
    tag_type: str,
    value: str,
    is_block: bool = True,
    tag_args: dict[str, str] | None = None,
) -> str:
    """Wrap value in HTML tag"""
    if is_block:
        value = f"\n{indent(2, value)}\n"
    start_tag = get_tag(tag_type, tag_args)
    return f"{start_tag}{value}</{tag_type}>"


def get_template(page_name: str, body: str = "") -> str:
    """Get template for page"""
    return f"""<!DOCTYPE HTML>
<html lang=en>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{page_name}</title>
    <style>
      * {{
        font-family: "Lucida Console";
      }}
      h1, footer {{
        text-align: center;
      }}
      footer {{
        position: absolute;
        bottom: 0;
        width: 100%;
      }}
    </style>
  </head>
  <body>
    <h1>{page_name}</h1>
{indent(4, body)}
  </body>
</html>"""


#     <footer>
#       <hr>
#       <p>{__title__} v{__version__} © {__author__}</p>
#     </footer>
#   </body>
# </html>"""


def contain_in_box(inside: str, name: str | None = None) -> str:
    """Contain HTML in a box."""
    if name is not None:
        inside = f"<span>{name}</span>\n<br>\n" + inside
    return f"""
<div style="background: ghostwhite;
            padding: 4px;
            border: 1px solid lightgray;
            margin: 4px;">
{indent(2, inside)}
</div>"""[
        1:
    ]


def radio_select_dict(
    submit_name: str, options: dict[str, str], default: str | None = None
) -> str:
    """Create radio select from dictionary"""
    lines = []
    count = 0
    for display, value in options.items():
        cid = f"{submit_name}_{count}"
        args = {"type": "radio", "id": cid, "name": submit_name, "value": value}
        if value == default:
            args["checked"] = "checked"
        lines.append(get_tag("input", args))
        lines.append(wrap_tag("label", display, False, {"for": cid}))
        lines.append("<br>")
        count += 1
    return "\n".join(lines)


def radio_select_box(
    submit_name: str,
    options: dict[str, str],
    default: str | None = None,
    box_title: str | None = None,
) -> str:
    """Create radio select value box from dictionary and optional names"""
    radios = radio_select_dict(submit_name, options, default)
    return contain_in_box("<br>\n" + radios, box_title)


def field_select(
    field_id: str,
    field_title: str | None,
    *,
    field_type: str = "text",
    default: str | None = None,
) -> str:
    """Create input field"""
    lines = []
    args = {
        "type": field_type,
        "id": field_id,
        "name": field_id,
    }
    if default is not None:
        args["value"] = default
    lines.append(wrap_tag("label", field_title, False, {"for": field_id}))
    lines.append(get_tag("input", args))
    return "\n".join(lines)


def get_list(values: list[str]) -> str:
    """Return HTML list from values"""
    display = "\n".join(wrap_tag("li", v) for v in values)
    return wrap_tag("ul", display)


def get_form(
    form_id: str, contents: str, submit_display: str, form_title: str | None = None
) -> str:
    """Return HTML form"""
    submit = get_tag("input", {"type": "submit", "value": submit_display})
    html = f"""{contents}
<br>
{submit}"""
    title = ""
    if form_title is not None:
        title = f"<b>{form_title}</b>\n"
    return title + wrap_tag("form", html, True, {"name": form_id, "method": "post"})


def create_link(reference: str, display: str) -> str:
    """Create link to reference"""
    return wrap_tag("a", display, False, {"href": reference})
