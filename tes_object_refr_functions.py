import idc
import idaapi

from aenum import Enum

ptrSize = 8
pdbg = False

def hasChildrenOfType(classHierarchyDescriptor, typeName):
    repr(classHierarchyDescriptor)
    if classHierarchyDescriptor.hasChildren():
        children = classHierarchyDescriptor.getChildren()
        for child in children:
            # child = RTTIBaseClassDescriptor
            if child.typeDescriptor.name == typeName:
                return True
            else:
                if child.hasChildren():
                    return hasChildrenOfType(child.classHierarchyDescriptor, typeName)
                return False
    return False

class MemObject(object):
    def __init__(self, addr):
        self.addr = addr

class NullObject(object):
    def __init__(self, *args, **kwargs):
        super(NullObject, self).__init__(*args, **kwargs)

def RVA(rva_addr):
    return idaapi.get_imagebase() + rva_addr

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
        return "<BGSInventoryItem at 0x%X, TESForm: 0x%X, Stack: 0x%X, Name: %s>" % (self.addr, self.form.addr, self.stack.addr, self.getName(12))

    class Offset(Enum):
        form = 0
        stack = 8

    def getName(self, max_length=None):
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
        dynamic_cast = idaapi.Appcall.proto("msvcrt__RTDynamicCast", "PVOID __fastcall __RTDynamicCast (PVOID inptr, LONG VfDelta, PVOID SrcType, PVOID TargetType, BOOL isReference);")

        tes_full_name_ptr = dynamic_cast(self.form.addr, 0, 0x00000001436CB140, 0x00000001436CE220, 0).value

        if (tes_full_name_ptr != 0):
            get_full_name_cstr = idaapi.Appcall.proto("TESFullName::get_name_cstr", "PVOID __fastcall __RTDynamicCast (PVOID inptr);")
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
    def __init__(self, addr, t_type = None, t_size = None):
        super(TArray, self).__init__(addr)
        self.capacity = idc.Dword(addr + TArray.Offset.Capacity.value)
        self.count = idc.Dword(addr + TArray.Offset.Count.value)
        self.t_type = t_type

        self.entriesAddr = idc.Qword(addr + TArray.Offset.Entries.value)
        if t_type is None:
            self.Entries = NullObject()
        else:
            if (self.count <= 0):
                self.Entries = []
                return
            self.Entries = [t_type(i) for i in range(self.entriesAddr, self.entriesAddr + 16 * self.count, t_size)]

    def __repr__(self):
        type_name = "<unknown>" if self.t_type is None else self.t_type.__name__
        return "<tArray at 0x%X, Entries: 0x%X, count: %s, capacity: %s, type: %s>" % (self.addr, self.entriesAddr, self.count, self.capacity, type_name)

    class Offset(Enum):
        Entries = 0 # heap array of T
        Capacity = 0x8
        Count = 0x10

class BGSInventoryList(MemObject):
    def __init__(self, addr):
        super(BGSInventoryList, self).__init__(addr)
        self.Items = TArray(addr + BGSInventoryList.Offset.Items.value, BGSInventoryItem, 16)
        self.weight = idc.GetFloat(addr + BGSInventoryList.Offset.Weight.value)

    class Offset(Enum):
        Items   = 0x58 # TArray<BGSInventoryItem>
        Weight  = 0x70 # float (4 bytes)

class TESObjectREFR(MemObject):
    def __init__(self, addr):
        super(TESObjectREFR, self).__init__(addr)
        self.InventoryItems = BGSInventoryList(idc.Qword(addr + TESObjectREFR.Offset.InventoryList.value))
    
    def __repr__(self):
        name = VFTable(idc.Qword(self.addr)).RTTICompleteObjectLocator.RTTITypeDescriptor.name
        return "<TESObjectREFR at 0x%X, BGSInventoryList: 0x%X, Type:%s>" % (self.addr, self.InventoryItems.addr, name)

    class Offset(Enum):
        InventoryList = 0xF8

class VFTable(MemObject):
    def __init__(self, addr):
        super(VFTable, self).__init__(addr)

        ptrRTTICol = self.addr + VFTable.Offset.RTTICompleteObjectLocator.value
        rttiCOL = idc.Qword(ptrRTTICol)
        if pdbg: print("COLp: 0x%X" % (ptrRTTICol))
        if pdbg: print("COL : 0x%X" % (rttiCOL))
        self.RTTICompleteObjectLocator = RTTICompleteObjectLocator(rttiCOL)
        # if self.RTTICompleteObjectLocator is not None:

        # short names
        self.col = self.RTTICompleteObjectLocator

    def __repr__(self):
        name = self.RTTICompleteObjectLocator.RTTITypeDescriptor.name
        return "<VFTable at 0x%X, COL: 0x%X, Name: %s>" % (self.addr, self.RTTICompleteObjectLocator.addr, name)
    
    class Offset(Enum):
        RTTICompleteObjectLocator = - 0x8   # 0x8

class RTTICompleteObjectLocator(MemObject):
    def __init__(self, addr):
        super(RTTICompleteObjectLocator, self).__init__(addr)
        
        self.thisOffset = idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.this.value)
        self.ctorDisplacement = idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.ctorDisplacement.value)
        descriptorAddr = RVA(idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.rvaTypeDescriptor.value))
        if pdbg: print("RTD: 0x%X" % (descriptorAddr))
        self.RTTITypeDescriptor = RTTITypeDescriptor(descriptorAddr)
        hierarchyAddr = RVA(idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.rvaTypeHierarchy.value))
        if pdbg: print("RTH: 0x%X" % (hierarchyAddr))
        self.RTTIClassHierarchyDescriptor = RTTIClassHierarchyDescriptor(hierarchyAddr)
        # self.ObjectBase

        #short names
        self.rtd = self.RTTITypeDescriptor
        self.rhd = self.RTTIClassHierarchyDescriptor

    class Offset(Enum):
        signature           = 0x00  # 0x4
        this                = 0x04  # 0x4
        ctorDisplacement    = 0x08  # 0x4
        rvaTypeDescriptor   = 0x0C  # 0x4
        rvaTypeHierarchy    = 0x10  # 0x4
        rvaObjectBase       = 0x14  # 0x4

class RTTITypeDescriptor(MemObject):
    def __init__(self, addr):
        super(RTTITypeDescriptor, self).__init__(addr)
        nameAddr = addr + RTTITypeDescriptor.Offset.mangledName.value + RTTITypeDescriptor.NameOffset.classPrefix.value
        if pdbg: print("NAM: 0x%X" % (nameAddr))
        self.mangledName = idc.GetString(nameAddr)
        demangledName = idc.Demangle('??_7' + self.mangledName + '6B@', 8)
        if demangledName != None:
            demangledName = demangledName[0:len(demangledName)-11]
        self.name = demangledName

    def __repr__(self):
        return "<RTTITypeDescriptor at 0x%X, NAM: %s>" % (self.addr, self.name)

    class Offset(Enum):
        typeInfo            = 0x00  # 0x8
        internalRuntimeRef  = 0x08  # 0x8
        mangledName         = 0x10

    class NameOffset(Enum):
        classPrefix         = 0x4   # skips "class" prefix

class RTTIClassHierarchyDescriptor(MemObject):
    def __init__(self, addr):
        super(RTTIClassHierarchyDescriptor, self).__init__(addr)

        signatureAddr = addr + RTTIClassHierarchyDescriptor.Offset.signature.value
        attributesAddr = addr + RTTIClassHierarchyDescriptor.Offset.attributes.value
        numberOfItemsAddr = addr + RTTIClassHierarchyDescriptor.Offset.numberOfItems.value
        baseClassHierarchyArr = RVA(idc.Dword(addr + RTTIClassHierarchyDescriptor.Offset.rvaBaseClassArrRef.value))

        if pdbg: print("BCA: 0x%X" % (baseClassHierarchyArr))

        self.signature = idc.Dword(signatureAddr)
        self.attributes = idc.Dword(attributesAddr)
        self.numberOfItems = idc.Dword(numberOfItemsAddr)
        self.baseClassHierarchyArray = baseClassHierarchyArr

    def __repr__(self):
        return "<RTTITypeHierarchy at 0x%X, SIG: 0x%X, ATT: 0x%X, NUM: 0x%X>" % (self.addr, self.signature, self.attributes, self.numberOfItems)

    def getChildren(self):
        # iterate over Base Class Array
        children = []
        # 0-th child is reference to self
        for i in range(1, self.numberOfItems + 1):
            baseClassDescriptorAddr = RVA(idc.Dword(self.baseClassHierarchyArray + i * 4))
            baseClassDescriptor = RTTIBaseClassDescriptor(baseClassDescriptorAddr)
            children.append(baseClassDescriptor)
        return children

    def printChildren(self):
        print("Children:")
        # iterate over Base Class Array
        for baseClassDescriptor in self.getChildren():
            print(" - %s" % (baseClassDescriptor.typeDescriptor))

    def hasChildren(self):
        return self.numberOfItems > 0

    class Offset(Enum):
        signature          = 0x00  # 0x4
        attributes         = 0x04  # 0x4
        numberOfItems      = 0x08  # 0x4
        rvaBaseClassArrRef = 0x0C  # 0x4

class RTTIBaseClassDescriptor(MemObject):
    def __init__(self, addr):
        super(RTTIBaseClassDescriptor, self).__init__(addr)
        typeDescriptorAddr = RVA(idc.Dword(addr + RTTIBaseClassDescriptor.Offset.rvaTypeDescriptor.value))
        classHierarchyAddr = RVA(idc.Dword(addr + RTTIBaseClassDescriptor.Offset.rvaClassHierarchy.value))

        if pdbg: print("BCD : %X" % (typeDescriptorAddr))
        if pdbg: print("BCHD: %X" % (classHierarchyAddr))

        self.typeDescriptor = RTTITypeDescriptor(typeDescriptorAddr)
        self.numberOfSubElements = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.numOfSubElements.value)
        self.memberDisplacement = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.memberDisplacement.value)
        self.vftableDisplacement = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.vftableDisplacement.value)
        self.displacementWithinVFTable = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.displacementWithinVFTable.value)
        self.baseClassAttributes = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.baseClassAttributes.value)
        self.classHierarchyDescriptor = RTTIClassHierarchyDescriptor(classHierarchyAddr)
    
    def __repr__(self):
        return "<RTTIBaseClassDescriptor at 0x%X, RTD: 0x%X, NUM: 0x%s, MDS: 0x%s, VDS: 0x%s, DWV: 0x%s, BAT: 0x%X, BHD: 0x%X>" % (self.addr, self.typeDescriptor.addr, self.numberOfSubElements, self.memberDisplacement, self.vftableDisplacement, self.displacementWithinVFTable, self.baseClassAttributes, self.classHierarchyDescriptor.addr)

    def hasChildren(self):
        return self.numberOfSubElements > 0

    class Offset(Enum):
        rvaTypeDescriptor           = 0x00 # 0x4
        numOfSubElements            = 0x04 # 0x4
        memberDisplacement          = 0x08 # 0x4
        vftableDisplacement         = 0x0C # 0x4
        displacementWithinVFTable   = 0x10 # 0x4
        baseClassAttributes         = 0x14 # 0x4
        rvaClassHierarchy           = 0x18 # 0x4