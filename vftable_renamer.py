import idaapi
import idautils
import idc


# Ask for a prefix that will be added to subs in the specified range
func_prefix = idc.AskStr("vftable", "Enter a prefix that will be added to subs")

# [[441b119f]]
# Asks for a start address of a vftable. Function names in this range (start_addr-end_addr) will be renamed.
# 
# ---------------------------------------------------------------------------------------------
# Help for: idc.AskAddr
# Shows a popup window and asks for an address, returns BADADDR in case it entered incorrectly
# arg0 - the default address that will be shown in the popup (integer)
# arg1 - message to be shown in the popup
# ---------------------------------------------------------------------------------------------
# Help for: int('0x0000000142C79E00', 16)
# Converts a HEX string into integer
# arg1 - string to be converted to an integer
# arg2 - base of the number, passed as a string in the first argument (16 = HEX)
start_addr = idc.AskAddr(int('0x0000000142C79DF8', 16), "Enter a start address of a vftable")

# the same as [441b119f]
end_addr = idc.AskAddr(0, "Enter an end address of a vftable")

# bytes_str = idc.GetManyBytes(start_addr, 4, False)


# For each address in specified range (vftable) add a prefix to functions
# --------------------------------------------------------------------------------------------
# range help:
# arg1 start address of the vftable (for renaming functions)
# arg2 end address of the vftable (for renaming functions)
# 8 is the length of a pointer for x64 architecture
#   (64 bits)/(8 bits) == 8 bytes
# +1 needed for including the last addr
#---------------------------------------------------------------------------------------------
# Example:
# for i in range(int('0x0000000142C79DF8', 16), int('0x0000000142C79E10', 16) + 1, 8):
# ...  format(i, '#04x')
# ...
# '0x142c79df8'
# '0x142c79e00'
# '0x142c79e08'
# '0x142c79e10'
for i in range(start_addr, end_addr + 1, 8):
    # Read an offset of a function in vftable. Needed to get function name later
    func_addr = idc.Qword(i)

    # 
    func_name = idc.GetFunctionName(func_addr)

    # TODO: skip if the prefix isn't sub_XXX
    new_name = func_prefix + func_name

    idc.MakeName(func_addr, new_name)


#
# print("Function name is:")
# print(func_name)
# print hex(start_addr)
# print hex(end_addr)
