import idc
import idaapi
import traceback

from aenum import Enum

from DDE.Common.memobject import MemObject, NullObject, ConditionalFormat
from DDE.IDAHelpers.rva import RVA
from DDE.IDAHelpers.addtrace import addReadWriteTrace
from DDE.RTTI.msvcrt.descriptors import VFTable
from arch64 import x64RegInfo

ptrSize = 8
max_deepness = 10
max_hierarchy_deepness = 45
pdbg = False

def addTraceTo(ea_or_mem_obj, bpt_size = 1):
    if issubclass(type(ea_or_mem_obj), BGSInventoryList):
        print("Adding trace to BGSInventoryList...")
        for item in ea_or_mem_obj.Items.Entries:
           addReadWriteTrace(item.addr, bpt_size)
        print("Done.")
    elif issubclass(type(ea_or_mem_obj), MemObject):
        print("Adding trace to MemObject...")
        addReadWriteTrace(ea_or_mem_obj.addr)
        print("Done.")
    else:
        print("Adding trace to address...")
        addReadWriteTrace(ea_or_mem_obj, bpt_size)
        print("Done.")

class DeepnessExceededError(Exception):
    def __init__(self, message = "Deepness exceeded the maximum value."):

        # Call the base class constructor with the parameters it needs
        super(DeepnessExceededError, self).__init__(message)

class BSExtraData(MemObject):
    def __init__(self, addr, deepness = 0):
        super(BSExtraData, self).__init__(addr, deepness)
        self.Next = idc.Qword(addr + BSExtraData.Offset.PtrNext.value)
        self.Type = idc.Byte(addr + BSExtraData.Offset.Type.value)

    def toArray(self):
        deepness = 0
        deepness_max = 10
        result = [self]
        current = self
        while deepness < deepness_max:
            if current.Next == 0:
                break
            deepness = deepness + 1
            nextExtra = BSExtraData(current.Next, self.deepness + 1)
            result.append(nextExtra)
            current = nextExtra
        return result

    def getTypeName(self):
        return VFTable(idc.Qword(self.addr + BSExtraData.Offset.vftable.value)).RTTICompleteObjectLocator.RTTITypeDescriptor.name

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
    def __init__(self, addr, deepness = 0):
        super(StringCache, self).__init__(addr, deepness)

    class Entry(MemObject):
        def __init__(self, addr, deepness=0):
            super(StringCache.Entry, self).__init__(addr, deepness)
            
            self.state = idc.Dword(self.addr + StringCache.Entry.Offset.State.value)
            self.dataAddr = (self.addr + StringCache.Entry.Offset.PtrData.value) % x64RegInfo.MaxValue

        def hasCStrValue(self):
            return ((self.state >> 14) & 0b11) & 1 == 0
        
        def getCStrAddr(self):
            if self.hasCStrValue():
                return self.dataAddr % x64RegInfo.MaxValue
            
            externDataAddr = idc.Qword(self.addr + StringCache.Entry.Offset.PtrExternDataEntry.value)

            if externDataAddr == 0:
                return NullObject()
            
            if self.deepness >= max_deepness:
                raise DeepnessExceededError()
            
            return StringCache.Entry(externDataAddr, self.deepness + 1).getCStrAddr()

        class Offset(Enum):
            PtrNext             = 0
            State               = 0x08
            Length              = 0x0C
            PtrExternDataEntry  = 0x10
            PtrData             = 0x18

    class Ref(MemObject):
        def __init__(self, addr, deepness=0):
            super(StringCache.Ref, self).__init__(addr, deepness)
            self.entryAddr = idc.Qword(addr + StringCache.Ref.Offset.Entry.value)
            
            if self.entryAddr == 0:
                self.entry = NullObject()
            else:
                if deepness >= max_deepness:
                    self.entry = self.entryAddr
                else:
                    self.entry = StringCache.Entry(self.entryAddr, deepness + 1)
            
        def __repr__(self):
            return "<StringCache::Ref at 0x{:X}, Entry: 0x{:X}>".format(self.addr, self.entryAddr)

        def getCStr(self):
            return idc.GetString(self.getCStrAddr())

        def getCStrAddr(self):
            if type(self.entry) == StringCache.Entry:
                return self.entry.getCStrAddr()
            
            if self.deepness >= max_deepness:
                raise DeepnessExceededError()
            else:
                return StringCache.Entry(self.entryAddr, self.deepness).getCStrAddr()

        class Offset(Enum):
            Entry = 0

class BSFixedString(StringCache.Ref):
    def __init__(self, addr, deepness=0):
        super(BSFixedString, self).__init__(addr, deepness)
    
    def __repr__(self):
        value = None
        try:
            value = self.getCStr()
        except:
            if pdbg: traceback.print_exc()
        if value is None:
            value = "<unknown>"
        entry = ConditionalFormat(self.entry)
        return ("<BSFixedString at 0x{:X}, entry: " + entry.format + ", value: {}>").format(self.addr, entry.repr, value)

class TESFullname(MemObject):
    def __init__(self, addr, deepness=0):
        super(TESFullname, self).__init__(addr, deepness)
        self.nameAddr = addr + TESFullName.Offset.Name.value

        if deepness >= max_deepness:
            self.name = self.nameAddr
        else:
            self.name = BSFixedString(self.nameAddr)

    def __repr__(self):
        name = None
        if type(self.name) == BSFixedString:
            try:
                name = self.name.getCStr()
            except:
                if pdbg: traceback.print_exc()
                name = "<unknown>"

        return "<TESFullname at 0x{:X}, name: {}>".format(self.addr, name)

    class Offset(Enum):
        BSFixedString = 0x8

class ExtraTextDisplayData(BSExtraData):
    def __init__(self, addr, deepness = 0):
        super(ExtraTextDisplayData, self).__init__(addr, deepness)

    class Offset(Enum):
        Name                = 0x18
        PtrMessage          = 0x20
        PtrQuest            = 0x28
        Type                = 0x30
        PtrTextReplaceData  = 0x38
        NameLength          = 0x40

class ExtraDataList(MemObject):
    def __init__(self, addr, deepness = 0):
        super(ExtraDataList, self).__init__(addr, deepness)
        extraDataAddr = idc.Qword(addr + ExtraDataList.Offset.PtrBSExtraData.value)
        if extraDataAddr == 0:
            self.ExtraData = NullObject()
        else:
            if deepness >= max_deepness:
                self.ExtraData = extraDataAddr
            else:
                self.ExtraData = BSExtraData(extraDataAddr, deepness + 1)
                extraDataTypes = {
                    0x99: ExtraTextDisplayData
                }
                extraDataType = extraDataTypes.get(self.ExtraData.Type, BSExtraData)
                if (extraDataType != BSExtraData):
                    self.ExtraData = extraDataType(addr, deepness + 1)

    def __repr__(self):
        extra = ConditionalFormat(self.ExtraData)
        return ("<ExtraDataList at 0x{:X}, extraData: " + extra.format + ">").format(self.addr, extra.repr)

    def toArray(self):
        if type(self.ExtraData) == NullObject:
            return []
        return self.ExtraData.toArray()

    def getExtraDataTypeNames(self):
        result = []
        for extraData in self.toArray():
            result.append(extraData.getTypeName())
        return result

    def printExtraDataTypes(self):
        for extraDataName in self.getExtraDataTypeNames():
            print(extraDataName)

    def getExtraDataByType(self, extraDataType):
        # lock is skipped
        return self.ExtraData.getExtraDataByType(extraDataType)

    class Offset(Enum):
        PtrBSExtraData = 0x08

class BaseFormComponent(MemObject):
    def __init__(self, addr, deepness = 0):
        super(BaseFormComponent, self).__init__(addr, deepness)
        self.vftable = idc.Qword(addr + BaseFormComponent.Offset.vftable)

    class Offset(Enum):
        vftable = 0

class TESForm(MemObject):
    def __init__(self, addr, deepness = 0):
        super(TESForm, self).__init__(addr, deepness)
        self.formType = idc.Byte(addr + TESForm.Offset.FormType.value)
        self.flags = idc.Dword(addr + TESForm.Offset.Flags.value)
        self.formId = idc.Dword(addr + TESForm.Offset.FormId.value)

    def getVFTable(self):
        return VFTable(idc.Qword(self.addr), self.deepness + 1)
    
    def getName(self, max_length=None):
        name = None
        try:
            func_ea = idaapi.get_imagebase() + int('0x1599B0', 16)
            name = idc.GetString(idaapi.Appcall.proto(func_ea, "PVOID __fastcall TESFullName::possibly_getItemFullNameValue (PVOID inptr);")(self.addr).value)
        except:
            if pdbg: traceback.print_exc()

        if name is None:
            name = '<unknown>'

        return name

    def __repr__(self):
        typeName = "<unknown>"
        try:
            vftable = self.getVFTable()
            typeName = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name
        except:
            if pdbg: traceback.print_exc()
        
        return "<TESForm at 0x{:X}, type: 0x{:X}, flags: 0x{:X}, formId: {:X} name: {}, typeName: {}>".format(self.addr, self.formType, self.flags, self.formId, self.getName(), typeName)

    class Offset(Enum):
        Flags = 0x10
        FormId = 0x14
        FormType = 0x1A

class TESFullName(BaseFormComponent):
    def __init__(self, addr, deepness = 0):
        super(TESFullName, self).__init__(addr, deepness)
        fixedStringAddr = addr + TESFullName.Offset.Name.value
        if deepness >= max_deepness:
            self.Name = fixedStringAddr
        else:
            self.Name = BSFixedString(fixedStringAddr, deepness + 1)

    class Offset(Enum):
        Name = 0x08

class Stack(MemObject):
    def __init__(self, addr, deepness = 0):
        super(Stack, self).__init__(addr, deepness)
        nextStackAddr = idc.Qword(addr + Stack.Offset.PtrNextStack.value)
        if nextStackAddr == 0:
            self.NextStack = NullObject()
        else:
            if deepness >= max_deepness:
                self.NextStack = nextStackAddr
            else:
                self.NextStack = Stack(nextStackAddr, deepness + 1)
        extraDataListAddr = idc.Qword(addr + Stack.Offset.PtrExtraDataList.value)
        if extraDataListAddr == 0:
            self.ExtraDataList = NullObject()
        else:
            if deepness >= max_deepness:
                self.ExtraDataList = extraDataListAddr
            else:
                self.ExtraDataList = ExtraDataList(extraDataListAddr, deepness + 1)
        self.count = idc.Dword(addr + Stack.Offset.Count.value)
        self.flags = idc.Byte(addr + Stack.Offset.Flags.value)

    def __repr__(self):
        stack = ConditionalFormat(self.NextStack)
        extra = ConditionalFormat(self.ExtraDataList)

        try:
            return ("<Stack at 0x{:X}, count: {}, nextStack: " + stack.format + ", extraDataList: " + extra.format + ">").format(self.addr, self.count, stack.repr, extra.repr)
        except:
            if pdbg: traceback.print_exc()
            return "<error>"

    def hasNextStack(self):
        return type(self.NextStack) != NullObject

    def hasExtraDataList(self):
        return type(self.ExtraDataList) != NullObject

    def toArray(self):
        deepness = 0
        deepness_max = 10
        result = [self]
        current = self
        while deepness < deepness_max:
            if current.hasNextStack():
                current = self.NextStack
                result.append(current)
            else:
                break
            deepness = deepness + 1
        return result

    def isEquipped(self):
        return self.flags & Stack.Flags.IsEquipped.value != 0

    class Flags(Enum):
        IsEquipped = 0x7

    class Offset(Enum):
        PtrNextStack        = 0x10
        PtrExtraDataList    = 0x18
        Count               = 0x20
        Flags               = 0x24

class BGSInventoryItem(MemObject):
    def __init__(self, addr, deepness = 0):
        super(BGSInventoryItem, self).__init__(addr, deepness)

        formAddr = idc.Qword(addr + BGSInventoryItem.Offset.form.value)
        stackAddr = idc.Qword(addr + BGSInventoryItem.Offset.stack.value)

        if stackAddr == 0:
            self.stack = NullObject()
        else:
            if deepness >= max_deepness:
                self.stack = stackAddr
            else:
                self.stack = Stack(stackAddr, deepness + 1)
        
        if formAddr == 0:
            self.form = NullObject()
        else:
            if deepness >= max_deepness:
                self.form = formAddr
            else:
                self.form = TESForm(formAddr, deepness + 1)

    def __repr__(self):
        form = ConditionalFormat(self.form if self.deepness >= max_deepness else self.form.addr)
        stack = ConditionalFormat(self.stack if self.deepness >= max_deepness else self.stack.addr)
        
        return ("<BGSInventoryItem at 0x{:X}, TESForm: " + form.format + ", Stack: " + stack.format + ", Name: {}>").format(self.addr, form.repr, stack.repr, self.getName(12))


    class Offset(Enum):
        form = 0
        stack = 8

    def getName(self, max_length=None):
        itemName = None
        # this block can be completely replaced with:
        #itemName = idc.GetString(Appcall.proto("TESFullName::possibly_getItemFullNameValue", "PVOID __fastcall TESFullName::possibly_getItemFullNameValue (PVOID inptr);")(0x0000000103C3BAB8).value)
        #.text:00000001401599B0 TESFullName::possibly_getItemFullNameValue proc near

        # TODO: move to a separate library file
        try:
            dynamic_cast = idaapi.Appcall.proto("msvcrt__RTDynamicCast", "PVOID __fastcall __RTDynamicCast (PVOID inptr, LONG VfDelta, PVOID SrcType, PVOID TargetType, BOOL isReference);")
        except:
            # sometimes it has two underscore symbols, sometimes three
            dynamic_cast = idaapi.Appcall.proto("msvcrt___RTDynamicCast", "PVOID __fastcall __RTDynamicCast (PVOID inptr, LONG VfDelta, PVOID SrcType, PVOID TargetType, BOOL isReference);")

        tes_full_name_ptr = dynamic_cast(self.form if self.deepness >= max_deepness else self.form.addr, 0, 0x00000001436CB140, 0x00000001436CE220, 0).value

        if (tes_full_name_ptr != 0):
            func_ea = idaapi.get_imagebase() + int("0x52980", 16)
            get_full_name_cstr = idaapi.Appcall.proto(func_ea, "PVOID __fastcall TESFullName::get_name_cstr (PVOID inptr);")
            strAddr = get_full_name_cstr(tes_full_name_ptr).value
            if strAddr != 0:
                itemName = idc.GetString(strAddr)
                if itemName is not None:
                    if max_length is not None:
                        itemName = (itemName[:12] + '..') if len(itemName) > 75 else itemName

        if itemName is None:
            itemName = '<unknown>'
        return itemName

class TArray(MemObject):
    def __init__(self, addr, t_type = None, t_size = None, deepness = 0):
        super(TArray, self).__init__(addr, deepness)
        self.capacity = idc.Dword(addr + TArray.Offset.Capacity.value)
        self.count = idc.Dword(addr + TArray.Offset.Count.value)
        self.maxEntries = 300
        self.t_type = t_type

        self.entriesAddr = idc.Qword(addr + TArray.Offset.Entries.value)
        if t_type is None:
            self.Entries = NullObject()
        else:
            if deepness >= max_deepness:
                self.Entries = self.entriesAddr
            else:
                if (self.count <= 0) or (t_type is None) or (t_size is None):
                    self.Entries = []
                else:
                    self.Entries = [t_type(i, deepness + 1) for i in range(self.entriesAddr, self.entriesAddr + t_size * (self.count if self.count < self.maxEntries else self.maxEntries), t_size)]

    def __repr__(self):
        type_name = "<unknown>" if self.t_type is None else self.t_type.__name__
        return "<tArray at 0x%X, Entries: 0x%X, count: %s, capacity: %s, type: %s>" % (self.addr, self.entriesAddr, self.count, self.capacity, type_name)

    class Offset(Enum):
        Entries = 0 # heap array of T
        Capacity = 0x8
        Count = 0x10

class InventoryInterface(MemObject):
    def __init__(self, addr, deepness=0):
        super(InventoryInterface, self).__init__(addr, deepness)
        self.itemsAddr = self.addr + InventoryInterface.Offset.Items.value
        
        if (deepness >= max_deepness):
            self.Items = self.itemsAddr
        else:
            self.Items = TArray(self.itemsAddr, InventoryInterface.Entry, InventoryInterface.Entry.Size, deepness + 1)
    
    def __repr__(self):
        return "<InventoryInterface at 0x{:X}, items: 0x{:X}>".format(self.addr, self.itemsAddr)
    
    class Entry(MemObject):
        Size = 0xC
        def __init__(self, addr, deepness=0):
            super(InventoryInterface.Entry, self).__init__(addr, deepness)
            self.handleId = idc.Dword(self.addr + InventoryInterface.Entry.Offset.HandleId.value)
            self.ownerHandle = idc.Dword(self.addr + InventoryInterface.Entry.Offset.OwnerHandle.value)
            self.itemPosition = idc.Word(self.addr + InventoryInterface.Entry.Offset.ItemPosition.value)
            self.count = idc.Word(self.addr + InventoryInterface.Entry.Offset.Count.value)

        class Offset(Enum):
            HandleId =      0x0 # 0x4
            OwnerHandle =   0x4 # 0x4
            ItemPosition =  0x8 # 0x2
            Count        =  0xA # 0x2
        
        def __repr__(self):
            return "<InventoryInterface::Entry at 0x{:X}, handleId: 0x{:X}, ownerHandle: 0x{:X}, itemPos: {}, count: {}>".format(self.addr, self.handleId, self.ownerHandle, self.itemPosition, self.count)
    
    class Offset(Enum):
        Unk00 =                             0x0     # 0x8
        CountChangedEventDispatcher =       0x8     #
        FavoriteChangedEventDispatcher =    0x60    #
        Items =                             0xB8    # tArray<InventoryInterface.Entry>

class BGSInventoryList(MemObject):
    def __init__(self, addr, deepness = 0):
        super(BGSInventoryList, self).__init__(addr, deepness)
        self.weight = idc.GetFloat(addr + BGSInventoryList.Offset.Weight.value)
        inventoryItemsAddr = addr + BGSInventoryList.Offset.Items.value
        if (deepness >= max_deepness):
            self.Items = inventoryItemsAddr
        else:
            self.Items = TArray(inventoryItemsAddr, BGSInventoryItem, 16, deepness + 1)
    
    def __repr__(self):
        count = 0
        items = ConditionalFormat(self.Items)
        try:
            count = self.Items.count
        except:
            if pdbg: traceback.print_exc()
        return ("<BGSInventoryList at 0x{:X}, weight: {}, count: {}, items: "+ items.format + ">").format(self.addr, self.weight, count, items.repr)

    class Offset(Enum):
        Items   = 0x58 # TArray<BGSInventoryItem>
        Weight  = 0x70 # float (4 bytes)

class TESObjectREFR(TESForm):
    def __init__(self, addr, deepness = 0):
        super(TESObjectREFR, self).__init__(addr, deepness)
        inventoryListAddr = idc.Qword(addr + TESObjectREFR.Offset.InventoryList.value)

        if (deepness >= max_deepness):
            self.InventoryList = inventoryListAddr
        else:
            self.InventoryList = BGSInventoryList(inventoryListAddr, deepness + 1)
    
    def __repr__(self):
        return "<TESObjectREFR at 0x%X, BGSInventoryList: 0x%X, Form:\n  %s>" % (self.addr, self.InventoryList.addr, super(TESObjectREFR, self).__repr__())

    class Offset(Enum):
        InventoryList = 0xF8
    
class BGSKeyword(TESForm):
    def __init__(self, addr, deepness=0):
        super(BGSKeyword, self).__init__(addr, deepness)

        self.keywordAddr = addr + BGSKeyword.Offset.BSFixedString.value

        if (deepness >= max_deepness):
            self.keyword = self.keywordAddr
        else:
            self.keyword = BSFixedString(self.keywordAddr, deepness + 1)

    def __repr__(self):
        try:
            keyword = ConditionalFormat(self.keyword)
            return ("<BGSKeyword at 0x{:X}, value: " + keyword.format + ">").format(self.addr, keyword.repr)
        except Exception as e:
            traceback.print_exc()
        return ("<BGSKeyword at 0x{:X}, value: <unkown>>").format(self.addr)
    
    class Offset(Enum):
        BSFixedString = 0x20
