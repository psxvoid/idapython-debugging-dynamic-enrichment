import idc
from aenum import Enum


class BGSInventoryItem():
    def __init__(self, addr):
        self.addr = addr
        self.form = idc.Qword(addr + BGSInventoryItem.Offset.form.value)
        self.stack = idc.Qword(addr + BGSInventoryItem.Offset.stack.value)
    
    def __repr__(self):
        return "<BGSInventoryItem at 0x%X, TESForm: 0x%X, Stack: 0x%X>" % (self.addr, self.form, self.stack)

    class Offset(Enum):
        form = 0
        stack = 8

class TArray():
    def __init__(self, t_array_addr):
        self.addr = t_array_addr
        self.Capacity = idc.Dword(t_array_addr + TArray.Offset.Capacity.value)
        self.Count = idc.Dword(t_array_addr + TArray.Offset.Count.value)
        
        if (self.Count <= 0):
            self.Entries = []
            return

        entriesStartAddr = idc.Qword(t_array_addr + TArray.Offset.Entries.value)
        self.Entries = [BGSInventoryItem(i) for i in range(entriesStartAddr, entriesStartAddr + 16 * self.Count, 16)]

    class Offset(Enum):
        Entries = 0 # heap array of T
        Capacity = 0x8
        Count = 0x10

class BGSInventoryList():
    def __init__(self, inventory_list_addr):
        self.addr = inventory_list_addr
        self.Items = TArray(inventory_list_addr + BGSInventoryList.Offset.Items.value)

    class Offset(Enum):
        Items = 0x58 # TArray<BGSInventoryItem>

class TESObjectREFR():
    def __init__(self, tes_object_refr_addr):
        self.addr = tes_object_refr_addr
        self.InventoryItems = BGSInventoryList(idc.Qword(tes_object_refr_addr + TESObjectREFR.Offset.InventoryList.value))

    class Offset(Enum):
        InventoryList = 0xF8