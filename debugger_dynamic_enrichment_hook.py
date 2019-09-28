import idc
import idaapi

#from tes_object_refr_functions import *
idaapi.require('tes_object_refr_functions')

pdbg = False
pvrb = False

def scan_register(reg_str_name):
    regValue = idc.GetRegValue(reg_str_name)
    if pdbg: print("Reg scan: %s" % (reg_str_name))
    # TODO: iterate over scanners
    scanner = AddressScanner_VFTable()

    if pdbg: print("Reg Value: 0x%X" % (regValue))
    try:
        if scanner.getMatch(regValue):
            print("%s is %s" % (reg_str_name.upper(), scanner.getScanMessage()))
            return
    except Exception as e:
        if pdbg: print(e)
        pass

    if pdbg: print("scanning ptr..")

    ptr = idc.Qword(regValue)
    if pdbg: print("PTR0: 0x%X" % (ptr))

    try:
        if scanner.getMatch(ptr):
            print("%s points to 0x%X -> %s" % (reg_str_name.upper(), ptr, scanner.getScanMessage()))
            return
    except Exception as e:
        if pdbg: print(e)
        pass

    ptrPtr = idc.Qword(ptr)
    if pdbg: print("PTR1: 0x%X" % (ptrPtr))

    try:
        if scanner.getMatch(ptrPtr):
            print("%s points to 0x%X -> 0x%x -> %s" % (reg_str_name.upper(), ptr, ptrPtr, scanner.getScanMessage()))
            return
    except:
        pass


class AddressScanner_VFTable(object):
    def __init__(self, *args, **kwargs):
        super(AddressScanner_VFTable, self).__init__(*args, **kwargs)
    
    def getMatch(self, addr):
        try:
            vftable = tes_object_refr_functions.VFTable(addr)
            name = vftable.RTTICompleteObjectLocator.RTTITypeDescriptor.name
            if (name is None) or (len(name) <= 0):
                return False
            else:
                self.scanMessage = repr(vftable.RTTICompleteObjectLocator.RTTITypeDescriptor)
                return True
        except Exception as e:
            if pdbg: print(e)
            return False

    def getScanMessage(self):
        return self.scanMessage


x64registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def scanRegisters():
    if pvrb: print("scanning...")
    for reg in x64registers:
        scan_register(reg)
    print("scan completed.")

class MyDbgHook(idaapi.DBG_Hooks):
    """ Own debug hook class that implements the callback functions """

    def __init__(self, *args, **kwargs):
        super(MyDbgHook, self).__init__(*args, **kwargs)
        self.isInstalled = False

    def scan(self):
        print('Manual scan initiated...')
        scanRegisters()
        print('Manual scan completed.')

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
        scanRegisters()
        return 0

    def dbg_suspend_process(self):
        return

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        return 0

    def dbg_trace(self, tid, ea):
        return 0

    def dbg_step_into(self):
        if pvrb: print("Step into.")
        scanRegisters()

    def dbg_run_to(self, pid, tid=0, ea=0):
        if pvrb: print("Run to.")
        scanRegisters()
        return

    def dbg_step_over(self):
        if pvrb: print("Step over.")
        scanRegisters()
