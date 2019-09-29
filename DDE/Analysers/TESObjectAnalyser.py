import idc
import idaapi

import traceback

import tes_object_refr_functions

from DDE.Analysers.AnalyserBase import AnalyserBase

tes = tes_object_refr_functions
pdbg = False

class TESObjectAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(TESObjectAnalyser, self).__init__(*args, **kwargs)

    def getMatch(self, addr):
        try:
            tArray = tes.TArray(addr)
            if tArray.count > 0 and tArray.capacity > 0 and tArray.count < tArray.capacity and tArray.count <= 10000:
                self.getScanMessage = repr(tArray)
                return True
        except:
            if pdbg: traceback.print_exc()

        try:
            vftable = tes.VFTable(idc.Qword(addr))
            type_name = "TESObjectREFR"

            isTESObjectREFRName = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name == type_name
            hasTESObjectREFRSubClass = tes.hasChildrenOfType(vftable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if isTESObjectREFRName or hasTESObjectREFRSubClass:
                self.scanMessage = repr(tes.TESObjectREFR(addr))
                return True
            return False
        except Exception as e:
            if pdbg: traceback.print_exc()
            return False