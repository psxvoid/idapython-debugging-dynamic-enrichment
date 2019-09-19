import re

from pytest_bdd import given, then, scenario, parsers


@scenario(
    'debugger_dynamic_enrichment.feature',
    'Multiline step using sub indentation',
)
def specs_multiline():
    pass


@given(parsers.parse('I have a step with:\n{text}'))
def i_have_text(text):
    return text


@then('the text should be parsed with correct indentation')
def text_should_be_correct(i_have_text, text):
    assert i_have_text == text == 'Some\nExtra\nLines'