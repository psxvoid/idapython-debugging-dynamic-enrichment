import re
from pytest_bdd import given, when, then, scenario
from unittest.mock import patch

from idc_module_mock import idc
import debugger_dynamic_enrichment

@scenario('.\debugger_dynamic_enrichment.feature', 'Main module initialization should install debugger hooks')
def specs_main_module_initialization_should_install_debugger_hooks():
    """Main module initialization should install debugger hooks."""


@given('the script is ran for the first time')
def the_script_is_ran_for_the_first_time():
    """the script is ran for the first time."""


@when('the main module is loaded')
def the_main_module_is_loaded():
    """the main module is loaded."""

@patch('debugger_dynamic_enrichment.MyDbgHook')
@then('it should create a dubugger hook')
def it_should_create_a_dubugger_hook(MyDbgHookMock):
    """it should create a dubugger hook."""
    debugger_dynamic_enrichment.__init__("__main__")
    assert MyDbgHookMock.called
    #raise NotImplementedError
