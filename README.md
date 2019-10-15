# IDAPython Debugging Dynamic Enrichment (DDE) + Fallout 4 Helpers

## Basic use-case scenario:
1. Clone the repository
2. Start debugging session in IDA
3. Press Alt+F7 or go to File->"Script file..."
4. Select `debugger_dynamic_enrichment.py` and press "OK"

It will install the debugger hook. Now, each time the breakpoint be hit (or "step into"/"step over"/"run to") additional info about data in registers will be printed to the debug output window if found.

If you know a data structure's address (e.g. TESForm) in Fallout 4 then you can inspect it by creating a TESForm object and passing an address to the constructor:
````python
TESForm(0x000000000)
````

But to make TES objects available run `tesobjects.py` at least once.

Known limitations:
1. Works only on x64 platforms and only helpful with MSVC++
2. Very limited support of Fallout 4

## TES Objects Analysis Examples

BSFixedString:

![BSFixedString Example](resources\tes-analyser-examples\Example-Analysis-BSFixedString.png)

## Scripts description

### vftable_renamer.py

This simple script can be used for renaming a range of subs with default names in vftable.

Usage:
1. Select a range of subs, run the script
2. Enter a prefix that will be added to selected subs (e.g. "MyClass::") in a popup
3. Press "Enter"

Subs with default names will be renamed into "MyClass::sub_xxxxxxxx"

### hightlight_local_calls.py

This simple script can be used for highlighting local calls inside a currently opened function.
Much more powerful alternatives exist on the internet but they often run for too long for big executables.
