from ciastore import htmlgen

def test_indent_single() -> None:
    assert htmlgen.indent(4, 'cat') == '    cat'

def test_indent_lines() -> None:
    assert htmlgen.indent(4, 'cat\npotatoe') == '    cat\n    potatoe'

def test_indent_lines_indent_two() -> None:
    assert htmlgen.indent(2, 'cat\npotatoe') == '  cat\n  potatoe'

def test_deindent_single() -> None:
    assert htmlgen.deindent(4, '    cat') == 'cat'

def test_deindent_single_only_four() -> None:
    assert htmlgen.deindent(4, '     cat') == ' cat'

def test_deindent_lines() -> None:
    assert htmlgen.deindent(4, '    cat\n    potatoe') == 'cat\npotatoe'

def test_deindent_lines_level_seven() -> None:
    assert htmlgen.deindent(7, '       cat\n       potatoe') == 'cat\npotatoe'
