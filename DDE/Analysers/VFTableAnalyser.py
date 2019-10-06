import traceback

from DDE.Analysers.AnalyserBase import AnalyserBase
from DDE.RTTI.msvcrt.descriptors import VFTable

pdbg = False

class VFTableAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(VFTableAnalyser, self).__init__(*args, **kwargs)
    
    def getMatch(self, addr):
        try:
            vftable = VFTable(addr)
            name = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name
            if (name is None) or (len(name) <= 0):
                return False
            else:
                self.scanMessage = repr(vftable.RTTICompleteObjectLocator.RTTITypeDescriptor)
                return True
        except Exception as e:
            if pdbg: traceback.print_exc()
            return False