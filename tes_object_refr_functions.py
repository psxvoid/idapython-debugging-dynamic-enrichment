import idc
import idaapi

from aenum import Enum

class MemObject(object):
    def __init__(self, addr):
        self.addr = addr

class BSExtraData(MemObject):
    def __init__(self, addr):
        super(BSExtraData, self).__init__(addr)
        self.Next = idc.Qword(addr + BSExtraData.Offset.PtrNext.value)
        self.Type = idc.Byte(addr + BSExtraData.Offset.Type.value)

    def getExtraDataByType(self, extraDataType):
        flag = idc.Qword(self.addr + BSExtraData.Offset.field_10)
        if flag == 0:
            return None
        var1 = extraDataType >> 3
        if var1 < 0x1B:
            return None
        var2 = 1 << ((extraDataType & 0x7) & 0b11111111)

        if (idc.byte(var1 + flag) & var2) == 0:
            return None

        vftable = idc.Qword(self.addr + BSExtraData.Offset.vftable)
        if vftable == 0:
            return None

        current_extra_data_addr = self.addr
        while True:
            if idc.byte(current_extra_data_addr + BSExtraData.Offset.Type) == extraDataType:
                return current_extra_data_addr
            current_extra_data_addr = idc.Qword(current_extra_data_addr + BSExtraData.Offset.PtrNext)
            if current_extra_data_addr == 0:
                return None

    class Offset(Enum):
        vftable     = 0x00
        PtrNext     = 0x08
        field_10    = 0x10
        Type        = 0x12


class StringCache(MemObject):
    def __init__(self, addr):
        super(StringCache, self).__init__(addr)

    class Entry(object):
        class Offset(Enum):
            PtrNext             = 0
            State               = 0x08
            Length              = 0x0C
            PtrExternDataEntry  = 0x10
            PtrData             = 0x18
    class Ref(object):
        class Offset(Enum):
            Entry = 0

BSFixedString = StringCache.Entry

class ExtraTextDisplayData(BSExtraData):
    def __init__(self, addr):
        super(ExtraTextDisplayData, self).__init__(addr)

    class Offset(Enum):
        Name                = 0x18
        PtrMessage          = 0x20
        PtrQuest            = 0x28
        Type                = 0x30
        PtrTextReplaceData  = 0x38
        NameLength          = 0x40

class ExtraDataList(MemObject):
    def __init__(self, addr):
        super(ExtraDataList, self).__init__(addr)
        extraData = idc.Qword(addr + ExtraDataList.Offset.PtrBSExtraData.value)
        if extraData == 0:
            self.ExtraData = 0
        else:
            self.ExtraData = BSExtraData(extraData)
            extraDataTypes = {
                0x99: ExtraTextDisplayData
            }
            extraDataType = extraDataTypes.get(self.ExtraData.Type, BSExtraData)
            if (extraDataType != BSExtraData):
                self.ExtraData = extraDataType(addr)

    def GetExtraDataByType(self, extraDataType):
        # lock is skipped
        return self.ExtraData.getExtraDataByType(extraDataType)

    class Offset(Enum):
        PtrBSExtraData = 0x08

class BaseFormComponent(MemObject):
    def __init__(self, addr):
        super(BaseFormComponent, self).__init__(addr)
        self.vftable = idc.Qword(addr + BaseFormComponent.Offset.vftable)

    class Offset(Enum):
        vftable = 0

class TESForm(MemObject):
    def __init__(self, addr):
        super(TESForm, self).__init__(addr)

    class Offset(Enum):
        Flags = 0x10
        FormId = 0x14
        FormType = 0x1A

class TESFullName(BaseFormComponent):
    def __init__(self, addr):
        super(TESFullName, self).__init__(addr)
        self.Name = BSFixedString(0x08)

    class Offset(Enum):
        Name = 0x08

class Stack(MemObject):
    def __init__(self, addr):
        super(Stack, self).__init__(addr)
        nextStack = idc.Qword(addr + Stack.Offset.PtrNextStack.value)
        if nextStack == 0:
            self.NextStack = 0
        else:
            self.NextStack = Stack(nextStack)
        extraDataList = idc.Qword(addr + Stack.Offset.PtrExtraDataList.value)
        if extraDataList == 0:
            self.ExtraDataList = 0
        else:
            self.ExtraDataList = ExtraDataList(extraDataList)
        self.Count = idc.Dword(addr + Stack.Offset.Count.value)

    class Offset(Enum):
        PtrNextStack        = 0x10
        PtrExtraDataList    = 0x18
        Count               = 0x20

class BGSInventoryItem():
    def __init__(self, addr):
        self.addr = addr
        self.form = TESForm(idc.Qword(addr + BGSInventoryItem.Offset.form.value))
        self.stack = Stack(idc.Qword(addr + BGSInventoryItem.Offset.stack.value))
    
    def __repr__(self):
        return "<BGSInventoryItem at 0x%X, TESForm: 0x%X, Stack: 0x%X>" % (self.addr, self.form.addr, self.stack.addr)

    class Offset(Enum):
        form = 0
        stack = 8

    def getName(self):
        itemName = None
        # this block can be completely replaced with:
        #itemName = idc.GetString(Appcall.proto("TESFullName::possibly_getItemFullNameValue", "PVOID __fastcall TESFullName::possibly_getItemFullNameValue (PVOID inptr);")(0x0000000103C3BAB8).value)
        #.text:00000001401599B0 TESFullName::possibly_getItemFullNameValue proc near

        # based on .text:00000001401A6510 getItemNameStr_ByStackNumber
        # if self.stack.ExtraDataList != 0:
        #     if self.stack.ExtraDataList.Type == 0x99:
        #         extraTextDisplayData = self.stack.ExtraDataList.GetExtraDataByType(0x99)
        #         if extraTextDisplayData is not None:
        #             return
        # TODO: move to a separate library file
        dynamic_cast = idaapi.Appcall.proto("msvcrt___RTDynamicCast", "PVOID __fastcall __RTDynamicCast (PVOID inptr, LONG VfDelta, PVOID SrcType, PVOID TargetType, BOOL isReference);")

        tes_full_name_ptr = dynamic_cast(self.form.addr, 0, 0x00000001436CB140, 0x00000001436CE220, 0).value

        if (tes_full_name_ptr != 0):
            get_full_name_cstr = idaapi.Appcall.proto("TESFullName::get_name_cstr", "PVOID __fastcall __RTDynamicCast (PVOID inptr);")
            strAddr = get_full_name_cstr(tes_full_name_ptr).value
            if strAddr != 0:
                itemName = idc.GetString(strAddr)

        if itemName is None:
            itemName = '<unable_to_get_item_name>'
        return itemName

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
