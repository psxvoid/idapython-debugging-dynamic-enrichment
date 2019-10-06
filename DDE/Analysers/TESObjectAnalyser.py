import idc
import idaapi

import traceback

from tesobjects import BGSInventoryItem, TESObjectREFR, TESForm, TArray
from DDE.RTTI.msvcrt.descriptors import VFTable, hasChildrenOfType
from DDE.IDAHelpers.timeout import exit_after

from DDE.Analysers.AnalyserBase import AnalyserBase

pdbg = False

class TESObjectAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(TESObjectAnalyser, self).__init__(*args, **kwargs)
    
    @exit_after(2)
    def getMatch(self, addr):
        try:
            tArray = TArray(addr)
            if tArray.count > 0 and tArray.capacity > 0 and tArray.count < tArray.capacity and tArray.count <= 10000:
                self.getScanMessage = repr(tArray)
                return True
        except:
            if pdbg: traceback.print_exc()

        try:
            # BGSInventoryItem
            inventoryItem = BGSInventoryItem(addr)
            formVFTable = inventoryItem.form.getVFTable()

            type_name = "TESForm"
            hasTESForm = hasChildrenOfType(formVFTable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if hasTESForm and inventoryItem.stack.count > 0 and inventoryItem.stack.count < 20000:
                self.scanMessage = repr(inventoryItem)
                return True
        except:
            if pdbg: traceback.print_exc()

        try:
            # TESObjectREFR
            vftable = VFTable(idc.Qword(addr))
            type_name = "TESObjectREFR"

            isTESObjectREFRName = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name == type_name
            hasTESObjectREFRSubClass = hasChildrenOfType(vftable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if isTESObjectREFRName or hasTESObjectREFRSubClass:
                self.scanMessage = repr(TESObjectREFR(addr))
                return True
        except Exception as e:
            if pdbg: traceback.print_exc()

        try:
            # TESForm
            tesForm = TESForm(addr)
            vftable = tesForm.getVFTable()
            
            type_name = "TESForm"
            hasTESForm = hasChildrenOfType(vftable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if (hasTESForm):
                self.scanMessage = repr(tesForm)
                return True
        except:
            if pdbg: traceback.print_exc()

        return False