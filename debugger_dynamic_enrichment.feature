Scenario: Main module initialization should install debugger hooks
    Given the script is ran for the first time
    When the main module is loaded
    Then it should create a dubugger hook