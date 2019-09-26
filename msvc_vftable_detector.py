import idc
import idaapi

pdbg = False

def get_class_name(name_addr):
    " Src: https://blog.quarkslab.com/visual-c-rtti-inspection.html "
    s = idc.Demangle('??_7' + idc.GetString(name_addr + 4) + '6B@', 8)
    if s != None:
        return s[0:len(s)-11]
    else:
        return idc.GetString(name_addr)

def getVFTableName(ptr_to_vftable):
    if pdbg: print("PTR: %X" % (ptr_to_vftable))
    vftable = idc.Qword(ptr_to_vftable)      # RTTI vftable
    if pdbg: print("VFT: %X" % (vftable))
    rttiCOL = idc.Qword(vftable - 8)         # RTTI Complete Object Locator
    if pdbg: print("COL: %X" % (rttiCOL))
    classNameOffset = rttiCOL + 3 * 4
    if pdbg: print("NOF: %X" % (classNameOffset))
    typeDescriptor = idaapi.get_imagebase() + idc.Dword(classNameOffset)    # RTTI Type Descriptor
    if pdbg: print("RTD: %X" % (typeDescriptor))
    nameLoc = typeDescriptor + 2 * 8        # a class name offset in RTTI Type Descriptor
    if pdbg: print("NLO: %X" % (nameLoc))
    name = get_class_name(nameLoc)
    if pdbg: print("NAM: %s" % (name))
    return name

addr = idc.ScreenEA()

print("Name: %s" % (getVFTableName(addr)))