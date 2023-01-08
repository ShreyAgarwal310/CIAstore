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


@pytest.mark.parametrize(
    "type_,args,expect",
    [
        ("p", None, "<p>"),
        ("p", {"fish": "false"}, '<p fish="false">'),
        ("i", None, "<i>"),
        (
            "input",
            {"type": "radio", "id": "0", "name": "test", "value": "Example"},
            '<input type="radio" id="0" name="test" value="Example">',
        ),
    ],
)
def test_get_tag(type_: str, args: dict[str, str] | None, expect: str) -> None:
    assert htmlgen.get_tag(type_, args) == expect


@pytest.mark.parametrize(
    "type_,value,block,args,expect",
    [
        ("p", "value", False, None, "<p>value</p>"),
        ("p", "fish", False, {"fish": "false"}, '<p fish="false">fish</p>'),
        ("i", "italic", False, None, "<i>italic</i>"),
        (
            "input",
            "seven",
            False,
            {"type": "radio", "id": "0", "name": "test", "value": "Example"},
            '<input type="radio" id="0" name="test" value="Example">seven</input>',
        ),
    ],
)
def test_wrap_tag(
    type_: str,
    value: str,
    block: bool,
    args: dict[str, str] | None,
    expect: str,
) -> None:
    assert htmlgen.wrap_tag(type_, value, block, args) == expect
