import traceback

from DDE.Analysers.AnalyserBase import AnalyserBase
from DDE.RTTI.msvcrt.descriptors import VFTable

pdbg = False

class VFTableAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(VFTableAnalyser, self).__init__(*args, **kwargs)
    
    def getMatches(self, addr):
        results = []
        try:
            vftable = VFTable(addr)
            typeDescriptor = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor
            name = typeDescriptor.name
            if (name is None) or (len(name) <= 0):
                pass
            else:
                results.append(typeDescriptor)
        except Exception as e:
            if pdbg: traceback.print_exc()
        
        return results