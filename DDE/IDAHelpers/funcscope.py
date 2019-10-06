import idc

def GetFuncStartAddr(addr):
    return idc.GetFunctionAttr(addr, idc.FUNCATTR_START)

def GetFuncEndAddr(addr):
    return idc.PrevHead(idc.GetFunctionAttr(addr, idc.FUNCATTR_END))