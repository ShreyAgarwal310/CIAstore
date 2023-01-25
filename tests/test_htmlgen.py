import pytest

from ciastore import htmlgen


def test_indent_single() -> None:
    assert htmlgen.indent(4, "cat") == "    cat"


def test_indent_lines() -> None:
    assert htmlgen.indent(4, "cat\npotatoe") == "    cat\n    potatoe"


def test_indent_lines_indent_two() -> None:
    assert htmlgen.indent(2, "cat\npotatoe") == "  cat\n  potatoe"


def test_deindent_single() -> None:
    assert htmlgen.deindent(4, "    cat") == "cat"


def test_deindent_single_only_four() -> None:
    assert htmlgen.deindent(4, "     cat") == " cat"


def test_deindent_lines() -> None:
    assert htmlgen.deindent(4, "    cat\n    potatoe") == "cat\npotatoe"


def test_deindent_lines_level_seven() -> None:
    assert htmlgen.deindent(7, "       cat\n       potatoe") == "cat\npotatoe"


def test_css_style() -> None:
    assert htmlgen.css_style(
        value_="seven",
        property_with_should_be_dash="space value",
    ) == ["value: seven;", 'property-with-should-be-dash: "space value";']


def test_css() -> None:
    assert (
        htmlgen.css(("h1", "footer"), text_align="center")
        == "h1, footer {\n  text-align: center;\n}"
    )


@pytest.mark.parametrize(
    "type_,args,expect",
    (
        ("p", {}, "<p>"),
        ("p", {"fish": "false"}, '<p fish="false">'),
        ("i", {}, "<i>"),
        (
            "input",
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input type="radio" id="0" name="test" value="Example">',
        ),
    ),
)
def test_tag(type_: str, args: dict[str, str], expect: str) -> None:
    assert htmlgen.tag(type_, **args) == expect


@pytest.mark.parametrize(
    "type_,value,block,args,expect",
    [
        ("p", "value", False, {}, "<p>value</p>"),
        ("p", "fish", False, {"fish": "false"}, '<p fish="false">fish</p>'),
        ("i", "italic", False, {}, "<i>italic</i>"),
        (
            "input",
            "seven",
            False,
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input type="radio" id="0" name="test" value="Example">seven</input>',
        ),
    ],
)
def test_wrap_tag(
    type_: str,
    value: str,
    block: bool,
    args: dict[str, str],
    expect: str,
) -> None:
    assert htmlgen.wrap_tag(type_, value, block, **args) == expect


def test_template() -> None:
    assert (
        htmlgen.template(
            "Cat Page",
            "Cat Body",
            head="Cat Head",
            body_tag={"cat_name": "bob"},
            lang="lolcat",
        )
        == """<!DOCTYPE HTML>
<html lang="lolcat">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cat Page</title>
    Cat Head
  </head>
  <body cat-name="bob">
    Cat Body
  </body>
</html>"""
    )


def test_template_no_tag() -> None:
    assert (
        htmlgen.template(
            "Cat Page",
            "Cat Body",
            head="Cat Head",
        )
        == """<!DOCTYPE HTML>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cat Page</title>
    Cat Head
  </head>
  <body>
    Cat Body
  </body>
</html>"""
    )


def test_contain_in_box_none() -> None:
    assert (
        htmlgen.contain_in_box("inside woo")
        == """<div style="background-color: ghostwhite; padding: 2px; border: 2px solid lightgray; margin: 4px; display: inline-block;">
  inside woo
</div>"""
    )


def test_contain_in_box_named() -> None:
    assert (
        htmlgen.contain_in_box("inside different", "Names here")
        == """<div style="background-color: ghostwhite; padding: 2px; border: 2px solid lightgray; margin: 4px; display: inline-block;">
  <span>
    Names here
  </span>
  <br>
  inside different
</div>"""
    )


def test_radio_select_dict() -> None:
    assert (
        htmlgen.radio_select_dict("name_here", {"cat": "seven"})
        == """<input type="radio" id="name_here_0" name="name_here" value="seven">
<label for="name_here_0">cat</label>
<br>"""
    )


def test_radio_select_dict_lots_default() -> None:
    assert (
        htmlgen.radio_select_dict(
            "name_here", {"cat": "0", "fish": "1", "four": "3"}, default="0"
        )
        == """<input type="radio" id="name_here_0" name="name_here" value="0" checked="checked">
<label for="name_here_0">cat</label>
<br>
<input type="radio" id="name_here_1" name="name_here" value="1">
<label for="name_here_1">fish</label>
<br>
<input type="radio" id="name_here_2" name="name_here" value="3">
<label for="name_here_2">four</label>
<br>"""
    )


def test_radio_select_box() -> None:
    assert (
        htmlgen.radio_select_box(
            "name_here", {"cat": "seven"}, box_title="click to add title"
        )
        == """<div style="background-color: ghostwhite; padding: 2px; border: 2px solid lightgray; margin: 4px; display: inline-block;">
  <span>
    click to add title
  </span>
  <br>
  <br>
  <input type="radio" id="name_here_0" name="name_here" value="seven">
  <label for="name_here_0">cat</label>
  <br>
</div>"""
    )


def test_input_field_no_kwarg() -> None:
    assert (
        htmlgen.input_field("<id>", "woot")
        == """<label for="<id>">woot</label>
<input id="<id>" name="<id>">"""
    )


def test_input_field_with_type() -> None:
    assert (
        htmlgen.input_field("<id>", "woot", field_type="types woo")
        == """<label for="<id>">woot</label>
<input type="types woo" id="<id>" name="<id>">"""
    )


def test_input_field_attrs() -> None:
    assert (
        htmlgen.input_field(
            "<id>", "woot", field_type="types woo", attrs={"autoselect": ""}
        )
        == """<label for="<id>">woot</label>
<input type="types woo" id="<id>" name="<id>" autoselect="">"""
    )


def test_bullet_list() -> None:
    assert (
        htmlgen.bullet_list(["one", "two"], flag="bean")
        == """<ul flag="bean">
  <li>one</li>
  <li>two</li>
</ul>"""
    )


def test_create_link() -> None:
    assert (
        htmlgen.create_link("/ref", "title of lonk")
        == '<a href="/ref">title of lonk</a>'
    )


def test_link_list() -> None:
    assert (
        htmlgen.link_list({"/cat-page": "Cat memes", "/home": "Home page"})
        == """<ul>
  <li><a href="/cat-page">Cat memes</a></li>
  <li><a href="/home">Home page</a></li>
</ul>"""
    )


def test_form() -> None:
    assert (
        htmlgen.form(
            "form_id", "dis content woo", "hihi", "click to add title"
        )
        == """<b>click to add title</b>
<form name="form_id" method="post">
  dis content woo\n  <br>
  <input type="submit" value="hihi">
</form>"""
    )


def test_form_no_title() -> None:
    assert (
        htmlgen.form("form_id", "dis content woo", "hihi")
        == """<form name="form_id" method="post">
  dis content woo
  <br>
  <input type="submit" value="hihi">
</form>"""
    )
