import traceback, re
import idc

from DDE.Analysers.AnalyserBase import AnalyserBase

pdbg = True

class StringAnalyser(AnalyserBase):
    def __init__(self, *args, **kwargs):
        super(StringAnalyser, self).__init__(*args, **kwargs)
    
    def getMatches(self, addr):
        results = []
        try:
            string = idc.GetString(addr)

            if string is not None and len(string) > 3 and idc.get_str_type(addr) is not None:
                results.append(string)
        except Exception as e:
            if pdbg: traceback.print_exc()
        
        return results