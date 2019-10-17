import traceback
import idc
import idaapi

idaapi.require('.AnalyserBase', 'DDE.Analysers')
idaapi.require('.TESObjectAnalyser', 'DDE.Analysers')
idaapi.require('.VFTableAnalyser', 'DDE.Analysers')
idaapi.require('.FuncAnalyser', 'DDE.Analysers')
idaapi.require('arch64')
from DDE.Analysers.AnalyserBase import AnalyserBase
from DDE.Analysers.TESObjectAnalyser import TESObjectAnalyser
from DDE.Analysers.VFTableAnalyser import VFTableAnalyser
from DDE.Analysers.FuncAnalyser import FuncAnalyser
from arch64 import x64RegCommonList, x64Regs

pdbg = False
pvrb = False

def filter_results(override_list, results, prevResults = []):
    # process overriden_by_all list
    if (len(results) > 1):
        results = [result for result in results if not (type(result) in override_list["overriden_by_all"])]
    

    # process overriden_by list    
    filteredResults = []
    resultTypes = [type(t) for t in results + prevResults]

    for result in results + prevResults:
        replacementRequested = False
        for toOverride, overrideBy in override_list["overriden_by"].items():
            if (type(result) == toOverride):
                for replacement in overrideBy:
                    if replacement in resultTypes:
                        replacementRequested = True
                        break
            else:
                continue # only executed if the inner loop did NOT break
            break # only executed if the inner loop DID break
        if (not replacementRequested) and (result in results): filteredResults.append(result)
    
    return filteredResults

def scan_value(scanners, value):
    results = []
    for scanner in scanners:
        try:
            results = results + scanner.getMatches(value)
        except Exception as e:
            if pdbg: print(e)
    return results

def print_results(formatStr, results):
    for result in results:
        print(formatStr.format(repr(result)))

def scan_register(reg_str_name):
    regValue = idc.GetRegValue(reg_str_name)
    if pdbg: print("Reg scan: %s" % (reg_str_name))
    # TODO: iterate over scanners
    # scanners = AnalyserBase.__subclasses__()
    scanners = [TESObjectAnalyser(), VFTableAnalyser(), FuncAnalyser()]
    if pvrb: print("Found %s scanners." % (len(scanners)))

    # build override list:
    override_list = {
        "overriden_by": {},
        "overriden_by_all": [],
        "overrides_all": []
    }

    for scanner in scanners:
        override_list["overriden_by"].update(scanner.override_list["horizontal"]["overriden_by"])                                         # dict
        override_list["overriden_by_all"] = override_list["overriden_by_all"] + scanner.override_list["horizontal"]["overriden_by_all"]   # list
        override_list["overrides_all"] = override_list["overrides_all"] + scanner.override_list["horizontal"]["overrides_all"]            # list

    # scan registers
    results = scan_value(scanners, regValue)
    results = filter_results(override_list, results)
    print_results("{} is ".format(reg_str_name.upper()) + "{}", results)

    if pdbg: print("scanning ptr..")

    ptr = idc.Qword(regValue)
    if pdbg: print("PTR0: 0x%X" % (ptr))

    prevResults = results
    results = scan_value(scanners, ptr)
    results = filter_results(override_list, results, prevResults)
    print_results("{} points to ".format(reg_str_name.upper()) + "{}", results)

    ptrPtr = idc.Qword(ptr)
    if pdbg: print("PTR1: 0x%X" % (ptrPtr))
    
    prevResults = prevResults + results
    results = scan_value(scanners, ptrPtr)
    results = filter_results(override_list, results, prevResults)
    print_results("{} points to 0x{:X} -> ".format(reg_str_name.upper(), ptr) + "{}", results)

def scanRegisters():
    if pvrb: print("scanning...")
    for reg in x64RegCommonList:
        scan_register(reg)
    print("scan completed at RIP=0x{:X}.".format(idc.GetRegValue(x64Regs.RIP.value)))

class MyDbgHook(idaapi.DBG_Hooks):
    """ Own debug hook class that implements the callback functions """

    def __init__(self, *args, **kwargs):
        super(MyDbgHook, self).__init__(*args, **kwargs)
        self.isInstalled = False

    def scan(self, manual = True):
        if manual: print('Manual scan initiated...')
        scanRegisters()
        if manual: print('Manual scan completed.')
    
    def hook(self):
        if self.isInstalled:
            print("Debugger hook is already installed.")
            return
        else:
            print("Debugger hook is installing...")
            super(MyDbgHook, self).hook()
            self.isInstalled = True
            print("Debugger hook successfully installed.")

    def unhook(self):
        if self.isInstalled == False:
            print("Debugger hook is already uninstalled.")
            return
        else:
            print("Debugger hook is uninstalling...")
            super(type(self), self).unhook()
            print("Debugger hook successfully uninstalled.")
            self.isInstalled = False

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        return

    def dbg_process_exit(self, pid, tid, ea, code):
        return

    def dbg_library_unload(self, pid, tid, ea, info):
        return 0

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        return 0

    def dbg_process_detach(self, pid, tid, ea):
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        return

    def dbg_bpt(self, tid, ea):
        if pvrb: print("Breakpoint.")
        self.scan(False)
        return 0

    def dbg_suspend_process(self):
        return

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        return 0

    def dbg_trace(self, tid, ea):
        return 0

    def dbg_step_into(self):
        if pvrb: print("Step into.")
        self.scan(False)

    def dbg_run_to(self, pid, tid=0, ea=0):
        if pvrb: print("Run to.")
        self.scan(False)
        return

    def dbg_step_over(self):
        if pvrb: print("Step over.")
        self.scan(False)
