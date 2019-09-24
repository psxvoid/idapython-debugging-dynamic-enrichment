import idc
import idaapi
#from tes_string_functions import *

# insures that the module is reloaded
idaapi.require('tes_string_functions')

str_addr = idc.AskAddr(0, "Enter address of BSFixedString")

if str_addr is None:
    exit()

cstr = tes_string_functions.getCStrFromBSFixedString(str_addr)

# print hex value
print("cstr is: 0x%X" % (cstr))