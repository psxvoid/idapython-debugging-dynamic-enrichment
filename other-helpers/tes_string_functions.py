import idc
from aenum import Enum

UInt64MaxValue = 9223372036854775808

class BSFixedString(Enum):
     ptrEntry = 0 # ptr to StringCache::Entry

class StringCache_Entry(Enum):
    ptrNextEntry = 0 # qword pointer tp StringCache::Entry
    state = 0x8 # dword value
    length = 0xC # dword value
    ptrExternDataEntry = 0x10 # qword pointer tp StringCache::Entry
    data = 0x18 # cstr array of symbols

def StringCache_Entry_State_HasCStrValue(state):
    #print("state_shifted: %x" % (state >> 14))
    #print("has_cstr_value: %s" % ((state >> 14) & 0b11 & 1))
    return ((state >> 14) & 0b11) & 1 == 0
    # return is_bit_set(state, 15)

def getCStrFromBSFixedStringExternDataRecursively(extern_data_entry):
    entry_state = idc.Dword(extern_data_entry + StringCache_Entry.state.value)
    #print("RecursiveEntryState: 0x%x" % (entry_state))
    hasCStrValue = StringCache_Entry_State_HasCStrValue(entry_state)
    if hasCStrValue:
        #print("cst_value: 0x%x" % (extern_data_entry + StringCache_Entry.data.value))
        return (extern_data_entry + StringCache_Entry.data.value) % UInt64MaxValue
    else:
        return getCStrFromBSFixedStringExternDataRecursively(extern_data_entry + StringCache_Entry.ptrExternDataEntry.value) % UInt64MaxValue

# try get TESObjectREFR full name:
# fullname
#def getCStrFromBSFixedString(BSFixedStringAddr, regName):
def getCStrFromBSFixedString(bs_fixed_string):
    if bs_fixed_string is None:
        return 0
    strCacheEntry = idc.Qword(bs_fixed_string + BSFixedString.ptrEntry.value)
    #print("EntryData: 0x%x" % (strCacheEntry))
    if strCacheEntry is None:
        return 0
    entry_state = idc.Dword(strCacheEntry + StringCache_Entry.state.value)
    #print("EntryState: 0x%x" % (entry_state))
    hasCStrValue =  StringCache_Entry_State_HasCStrValue(entry_state)
    #print("hasCStrValue: %s" % (hasCStrValue))
    if hasCStrValue:
        return (strCacheEntry + StringCache_Entry.data.value) % UInt64MaxValue
    extern_data_entry = idc.Qword(strCacheEntry + StringCache_Entry.ptrExternDataEntry.value)
    #print("ExternDataEntry: 0x%x" % (extern_data_entry))
    return getCStrFromBSFixedStringExternDataRecursively(extern_data_entry)

