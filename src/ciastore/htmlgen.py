"""HTML Generation - Generate HTML programatically"""


from collections.abc import Generator


def indent(level: int, text: str) -> str:
    """Indent text by level of spaces."""
    prefix = " " * level
    return "\n".join(prefix + line for line in text.splitlines())


def deindent(level: int, text: str) -> str:
    """Undo indent on text by level of characters."""
    prefix = " " * level
    return "\n".join(line.removeprefix(prefix) for line in text.splitlines())


TagArg = str | int | float | bool


def _quote_strings(values: TagArg) -> Generator[str, None, None]:
    """Wrap string arguments with spaces in quotes"""
    for value in values:
        if isinstance(value, str) and " " in value:
            yield f'"{value}"'
            continue
        yield f"{value}"


def _process_properties(
    properties: dict[str, TagArg | list[TagArg] | tuple[TagArg, ...]]
) -> Generator[str, None, None]:
    """Yield declarations"""
    for key, values in properties.items():
        property_ = key.removesuffix("_").replace("_", "-")
        if isinstance(values, (list, tuple)):
            wrap = values
        else:
            wrap = (values,)
        value = " ".join(_quote_strings(wrap))
        yield f"{property_}: {value}"


def css_style(
    **kwargs: TagArg | list[TagArg] | tuple[TagArg, ...]
) -> list[str]:
    """Return css style block"""
    return [f"{prop};" for prop in _process_properties(kwargs)]


def css(
    selector: str | list[str] | tuple[str, ...],
    **kwargs: TagArg | list[TagArg] | tuple[TagArg, ...],
) -> str:
    """Return CSS block"""
    if isinstance(selector, (list, tuple)):
        selector = ", ".join(selector)
    properties = indent(2, "\n".join(css_style(**kwargs)))
    return f"{selector} {{\n{properties};\n}}"


def _process_tag_args(args: dict[str, TagArg]) -> Generator[str, None, None]:
    """Remove trailing underscores for arguments"""
    for name, value in args.items():
        key = name.removesuffix("_").replace("_", "-")
        yield f'{key}="{value}"'


def tag(type_: str, **kwargs: TagArg) -> str:
    """Return HTML tag. Removes trailing underscore from argument names."""
    args = ""
    if kwargs:
        args = " " + " ".join(_process_tag_args(kwargs))
    return f"<{type_}{args}>"


def wrap_tag(
    type_: str,
    value: str,
    block: bool = True,
    **kwargs: TagArg,
) -> str:
    """Wrap value in HTML tag.

    If block, indent value"""
    if block and value:
        value = f"\n{indent(2, value)}\n"
    start_tag = tag(type_, **kwargs)
    return f"{start_tag}{value}</{type_}>"


def template(
    title: str,
    body: str,
    *,
    head: str = "",
    body_tag: dict[str, TagArg] | None = None,
    lang: str = "en",
) -> str:
    """Get template for page"""
    if body_tag is None:
        body_tag = {}
    head_content = "\n".join(
        (
            tag("meta", charset="utf-8"),
            tag(
                "meta",
                name="viewport",
                content="width=device-width, initial-scale=1",
            ),
            wrap_tag("title", title, False),
            head,
        )
    )

    html_content = "\n".join(
        (
            wrap_tag("head", head_content),
            wrap_tag("body", body, **body_tag),
        )
    )

    return "\n".join(
        (
            tag("!DOCTYPE HTML"),
            wrap_tag(
                "html",
                html_content,
                lang=lang,
            ),
        )
    )


def contain_in_box(inside: str, name: str | None = None) -> str:
    """Contain HTML in a box."""
    if name is not None:
        inside = "\n".join(
            (
                wrap_tag("span", name),
                tag("br"),
                inside,
            )
        )
    return wrap_tag(
        "div",
        inside,
        style=" ".join(
            css_style(
                background_color="ghostwhite",
                padding="2px",
                border=("2px", "solid", "lightgray"),
                margin="4px",
            )
        ),
    )


def radio_select_dict(
    submit_name: str, options: dict[str, str], default: str | None = None
) -> str:
    """Create radio select from dictionary"""
    lines = []
    count = 0
    for display, value in options.items():
        cid = f"{submit_name}_{count}"
        args = {
            "type": "radio",
            "id": cid,
            "name": submit_name,
            "value": value,
        }
        if value == default:
            args["checked"] = "checked"
        lines.append(tag("input", **args))
        lines.append(wrap_tag("label", display, False, **{"for": cid}))
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


def input_field(
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
    if field_title is not None:
        # lintcheck: too-many-function-args (E1121): Too many positional arguments for function call
        lines.append(wrap_tag("label", field_title, False, {"for": field_id}))
    # lintcheck: too-many-function-args (E1121): Too many positional arguments for function call
    lines.append(tag("input", args))
    return "\n".join(lines)


def bullet_list(values: list[str]) -> str:
    """Return HTML list from values"""
    display = "\n".join(wrap_tag("li", v) for v in values)
    return wrap_tag("ul", display)


def form(
    form_id: str,
    contents: str,
    submit_display: str,
    form_title: str | None = None,
) -> str:
    """Return HTML form"""
    # lintcheck: too-many-function-args (E1121): Too many positional arguments for function call
    submit = tag("input", {"type": "submit", "value": submit_display})
    html = f"""{contents}
<br>
{submit}"""
    title = ""
    if form_title is not None:
        title = f"<b>{form_title}</b>\n"
    args = {"name": form_id, "method": "post"}
    # lintcheck: too-many-function-args (E1121): Too many positional arguments for function call
    return title + wrap_tag("form", html, True, args)


def create_link(reference: str, display: str) -> str:
    """Create link to reference"""
    # lintcheck: too-many-function-args (E1121): Too many positional arguments for function call
    return wrap_tag("a", display, False, {"href": reference})


# lintcheck: trailing-newlines (C0305): Trailing newlines
