"""Test elapsed."""

import pytest
from ciastore import elapsed


def test_split_time() -> None:
    assert elapsed.split_time(1234567891011121314) == [
        78,
        1,
        4,
        7,
        891,
        0,
        1,
        3,
        9,
        2,
        3,
        9,
        1,
        54,
    ]


def test_combine_end() -> None:
    assert elapsed.combine_end(("Cat", "fish", "potato")) == "Cat, fish, and potato"


def test_combine_end_two() -> None:
    assert elapsed.combine_end(("fish", "taco")) == "fish and taco"


def test_combine_end_diff_final() -> None:
    assert elapsed.combine_end(("one", "two", "tree"), "or") == "one, two, or tree"


def test_get_elapsed() -> None:
    assert (
        elapsed.get_elapsed(1234567891011121314)
        == "78 eons, 1 era, 4 epochs, 7 ages, 891 millennia, 1 decade, 3 years, 9 months, 2 weeks, 3 days, 9 hours, 1 minute, and 54 seconds"
    )


def test_get_elapsed_negative() -> None:
    assert (
        elapsed.get_elapsed(-1234567891011121314)
        == "Negative 78 eons, 1 era, 4 epochs, 7 ages, 891 millennia, 1 decade, 3 years, 9 months, 2 weeks, 3 days, 9 hours, 1 minute, and 54 seconds"
    )


def test_split_end() -> None:
    assert elapsed.split_end(
        "78 eons, 1 era, 4 epochs, 7 ages, 891 millennia, 1 decade, 3 years, 9 months, 2 weeks, 3 days, 9 hours, 1 minute, and 54 seconds",
    ) == [
        "78 eons",
        "1 era",
        "4 epochs",
        "7 ages",
        "891 millennia",
        "1 decade",
        "3 years",
        "9 months",
        "2 weeks",
        "3 days",
        "9 hours",
        "1 minute",
        "54 seconds",
    ]


@pytest.mark.parametrize(
    ("hour", "expect"),
    [
        (0, "Night"),
        (1, "Night"),
        (2, "Night"),
        (3, "Night"),
        (4, "Night"),
        (5, "Morning"),
        (6, "Morning"),
        (7, "Morning"),
        (8, "Morning"),
        (9, "Morning"),
        (10, "Morning"),
        (11, "Morning"),
        (12, "Afternoon"),
        (13, "Afternoon"),
        (14, "Afternoon"),
        (15, "Afternoon"),
        (16, "Afternoon"),
        (17, "Afternoon"),
        (18, "Afternoon"),
        (19, "Evening"),
        (20, "Evening"),
        (21, "Evening"),
        (22, "Night"),
        (23, "Night"),
        (24, "Night"),
    ],
)
def test_get_time_of_day(hour: int, expect: str) -> None:
    assert elapsed.get_time_of_day(hour) == expect
