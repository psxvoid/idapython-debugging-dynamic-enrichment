import idaapi
import idautils
import idc


# sys.maxsize+1
UInt64MaxValue = 9223372036854775808

def getTESObjectREFR(handle):
    # sys.maxsize -     needed for getting int64 value in python (ignore overflow > int64). Needed for be compliant with 64 bit registers
    # sys.maxsize + 1 - needed because sys.maxsize returns int64-1
    return (idc.Qword((handle & int('0x1FFFFF', 16)) * 16 + int('0x1438CD030', 16) + 8) + int('0xFFFFFFFFFFFFFFE0', 16)) % UInt64MaxValue

handle = idc.AskStr("0x200000", "Enter a prefix that will be added to subs")
handle = int(handle, 16)
# handle = int('0x200000', 16)
# handle = int('0x21A048', 16)
# handle = idc.Dword(RCX)

tesObjectREFR = getTESObjectREFR(handle)
print("TESObjectREFR:")
print hex(tesObjectREFR)