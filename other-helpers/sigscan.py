import idc

def relocGlobalVar(sigStr, relativeOffset = 0, dataOffset = 0, instructionLength = 0):
    sigAddr = idc.FindBinary(0, idc.SEARCH_DOWN, sigStr)
    scanResult = sigAddr + relativeOffset
    if (dataOffset != None):
        rel32 = idc.Dword(scanResult + dataOffset)
        scanResult = scanResult + instructionLength + rel32
    return scanResult

def getInventoryInterfacePtr():
    return relocGlobalVar("48 8B FA 48 8B D9 74 ? 48 8B D1", 11, 3, 7)

def getPlayerPtr():
    return relocGlobalVar("48 8B 05 ? ? ? ? 48 85 C0 74 0C F0 FF 40 28", 0, 3, 7)