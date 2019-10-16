import idc
import idaapi

import traceback

from tesobjects import BGSInventoryItem, TESObjectREFR, TESForm, TArray, BSFixedString

from DDE.RTTI.msvcrt.descriptors import VFTable, RTTITypeDescriptor, hasChildrenOfType
from DDE.IDAHelpers.timeout import exit_after
from DDE.IDAHelpers.adressing import isInMemoryRange

from DDE.Analysers.AnalyserBase import AnalyserBase

from DDE.IDAHelpers.wrappers.idafunc_func_t import IDAFunc

pdbg = False

class TESObjectAnalyser(AnalyserBase):
    override_list = {
        "horizontal": {
            "overriden_by": {
                IDAFunc: [VFTable, TESObjectREFR, RTTITypeDescriptor],
                RTTITypeDescriptor: [TESForm, TESObjectREFR, BGSInventoryItem],
                TESForm: [TESObjectREFR, BGSInventoryItem],
            },
            "overriden_by_all": [BSFixedString],
            "overrides_all": [],
        }
    }

    def __init__(self, *args, **kwargs):
        super(TESObjectAnalyser, self).__init__(*args, **kwargs)
    
    @exit_after(2)
    def getMatches(self, addr):
        results = []

        if not isInMemoryRange(addr):
            return results

        try:
            # tArray
            tArray = TArray(addr)
            if tArray.count > 0 and tArray.capacity > 0 and tArray.count < tArray.capacity and tArray.count <= 10000 and isInMemoryRange(tArray.entriesAddr):
                results.append(tArray)
        except:
            if pdbg: traceback.print_exc()

        try:
            # BGSInventoryItem
            inventoryItem = BGSInventoryItem(addr)
            formVFTable = inventoryItem.form.getVFTable()

            type_name = "TESForm"
            hasTESForm = hasChildrenOfType(formVFTable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if hasTESForm and inventoryItem.stack.count > 0 and inventoryItem.stack.count < 20000:
                results.append(inventoryItem)
        except:
            if pdbg: traceback.print_exc()

        try:
            # TESObjectREFR
            vftable = VFTable(idc.Qword(addr))
            type_name = "TESObjectREFR"

            isTESObjectREFRName = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name == type_name
            hasTESObjectREFRSubClass = hasChildrenOfType(vftable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if isTESObjectREFRName or hasTESObjectREFRSubClass:
                results.append(TESObjectREFR(addr))
        except Exception as e:
            if pdbg: traceback.print_exc()

        try:
            # TESForm
            tesForm = TESForm(addr)
            vftable = tesForm.getVFTable()
            
            type_name = "TESForm"
            hasTESForm = hasChildrenOfType(vftable.RTTICompleteObjectLocator.RTTIClassHierarchyDescriptor, type_name)

            if (hasTESForm):
                results.append(tesForm)
        except:
            if pdbg: traceback.print_exc()
        
        try:
            # BSFixedString
            fixedString = BSFixedString(addr)
            cstr = fixedString.getCStr()
            if (len(cstr) > 1):
                results.append(fixedString)
        except:
            if pdbg: traceback.print_exc()            

        return results