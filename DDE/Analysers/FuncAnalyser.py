import traceback
import idaapi

from DDE.Analysers.AnalyserBase import AnalyserBase
from DDE.IDAHelpers.wrappers.idafunc_func_t import IDAFunc

pdbg = False

class FuncAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(FuncAnalyser, self).__init__(*args, **kwargs)
    
    def getMatches(self, addr):
        results = []
        try:
            func = IDAFunc(addr)

            if (not func.empty()) and (func.start_ea == addr):
                results.append(func)
        except Exception as e:
            if pdbg: traceback.print_exc()
        
        return results