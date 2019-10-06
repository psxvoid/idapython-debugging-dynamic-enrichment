import idc

from aenum import Enum

from DDE.Common.memobject import MemObject
from DDE.IDAHelpers.rva import RVA

ptrSize = 8
max_deepness = 10
max_hierarchy_deepness = 45

class VFTable(MemObject):
    def __init__(self, addr, deepness = 0):
        super(VFTable, self).__init__(addr, deepness)

        ptrRttiCol = self.addr + VFTable.Offset.RTTICompleteObjectLocator.value
        rttiCOLAddr = idc.Qword(ptrRttiCol)

        if deepness >= max_deepness:
            self.RTTICompleteObjectLocator = rttiCOLAddr
        else:
            self.RTTICompleteObjectLocator = RTTICompleteObjectLocator(rttiCOLAddr, deepness + 1)

        # short names
        self.col = self.RTTICompleteObjectLocator

    def __repr__(self):
        name = self.RTTICompleteObjectLocator.RTTITypeDescriptor.name
        return "<VFTable at 0x%X, COL: 0x%X, Name: %s>" % (self.addr, self.RTTICompleteObjectLocator.addr, name)
    
    class Offset(Enum):
        RTTICompleteObjectLocator = - 0x8   # 0x8

class RTTICompleteObjectLocator(MemObject):
    def __init__(self, addr, deepness = 0):
        super(RTTICompleteObjectLocator, self).__init__(addr, deepness)
        
        self.thisOffset = idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.this.value)
        self.ctorDisplacement = idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.ctorDisplacement.value)
        descriptorAddr = RVA(idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.rvaTypeDescriptor.value))
        hierarchyAddr = RVA(idc.Dword(self.addr + RTTICompleteObjectLocator.Offset.rvaTypeHierarchy.value))

        if deepness >= max_deepness:
            self.RTTITypeDescriptor = descriptorAddr
            self.RTTIClassHierarchyDescriptor = hierarchyAddr
        else:
            self.RTTITypeDescriptor = RTTITypeDescriptor(descriptorAddr, deepness + 1)
            self.RTTIClassHierarchyDescriptor = RTTIClassHierarchyDescriptor(hierarchyAddr, deepness + 1)

        # TODO: add self.ObjectBase

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
    def __init__(self, addr, deepness = 0):
        super(RTTITypeDescriptor, self).__init__(addr, deepness)
        nameAddr = addr + RTTITypeDescriptor.Offset.mangledName.value + RTTITypeDescriptor.NameOffset.classPrefix.value
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
    def __init__(self, addr, deepness = 0):
        super(RTTIClassHierarchyDescriptor, self).__init__(addr, deepness)

        signatureAddr = addr + RTTIClassHierarchyDescriptor.Offset.signature.value
        attributesAddr = addr + RTTIClassHierarchyDescriptor.Offset.attributes.value
        numberOfItemsAddr = addr + RTTIClassHierarchyDescriptor.Offset.numberOfItems.value
        baseClassHierarchyArrAddr = RVA(idc.Dword(addr + RTTIClassHierarchyDescriptor.Offset.rvaBaseClassArrRef.value))

        self.signature = idc.Dword(signatureAddr)
        self.attributes = idc.Dword(attributesAddr)
        self.numberOfItems = idc.Dword(numberOfItemsAddr)
        self.baseClassHierarchyArray = baseClassHierarchyArrAddr

    def __repr__(self):
        return "<RTTITypeHierarchy at 0x%X, SIG: 0x%X, ATT: 0x%X, NUM: 0x%X>" % (self.addr, self.signature, self.attributes, self.numberOfItems)

    def getChildren(self, max_children = 50):
        # iterate over Base Class Array
        children = [] 
        if self.numberOfItems > max_children:
            return children

        # 0-th child is reference to self
        for i in range(1, self.numberOfItems + 1):
            baseClassDescriptorAddr = RVA(idc.Dword(self.baseClassHierarchyArray + i * 4))
            baseClassDescriptor = None
            if self.deepness >= max_deepness:
                baseClassDescriptor = baseClassDescriptorAddr
            else:
                baseClassDescriptor = RTTIBaseClassDescriptor(baseClassDescriptorAddr, self.deepness + 1)
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
    def __init__(self, addr, deepness = 0):
        super(RTTIBaseClassDescriptor, self).__init__(addr, deepness)
        typeDescriptorAddr = RVA(idc.Dword(addr + RTTIBaseClassDescriptor.Offset.rvaTypeDescriptor.value))
        classHierarchyAddr = RVA(idc.Dword(addr + RTTIBaseClassDescriptor.Offset.rvaClassHierarchy.value))

        self.numberOfSubElements = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.numOfSubElements.value)
        self.memberDisplacement = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.memberDisplacement.value)
        self.vftableDisplacement = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.vftableDisplacement.value)
        self.displacementWithinVFTable = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.displacementWithinVFTable.value)
        self.baseClassAttributes = idc.Dword(addr + RTTIBaseClassDescriptor.Offset.baseClassAttributes.value)

        if deepness >= max_deepness:
            self.typeDescriptor = typeDescriptorAddr
            self.classHierarchyDescriptor = classHierarchyAddr
        else:
            self.typeDescriptor = RTTITypeDescriptor(typeDescriptorAddr, deepness + 1)
            self.classHierarchyDescriptor = RTTIClassHierarchyDescriptor(classHierarchyAddr, deepness + 1)
    
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

def hasChildrenOfType(classHierarchyDescriptor, typeName, deepness = 0):
    if deepness >= max_hierarchy_deepness: return False
    if classHierarchyDescriptor.hasChildren():
        children = classHierarchyDescriptor.getChildren(max_hierarchy_deepness)
        for child in children:
            # child = RTTIBaseClassDescriptor
            if child.typeDescriptor.name == typeName:
                return True
            else:
                if child.hasChildren():
                    return hasChildrenOfType(child.classHierarchyDescriptor, typeName, deepness + 1)
                return False
    return False