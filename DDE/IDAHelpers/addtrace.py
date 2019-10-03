import idc
import ida_dbg

from aenum import Constant

class AddTraceError(Exception):
    def __init__(self, addr, message = None):
        super(AddTraceError, self).__init__()
        self.addr = addr
        self.message = message

    def __repr__(self):
        return "<AddTraceError at address: 0x{:X}, message: {}>".format(self.addr, self.message)

class BreakpointMode(Constant):
    ReadWrite = 3

def addReadWriteTrace(addr, bpt_size = 1):
    result = idc.add_bpt(addr, bpt_size, BreakpointMode.ReadWrite)
    if result == False:
        raise AddTraceError(addr, "Unable to set breakpoint at the given address.")
    pbpt = ida_dbg.bpt_t()
    ida_dbg.get_bpt(addr, pbpt)
    pbpt.flags = 10
    result = ida_dbg.update_bpt(pbpt)
    if result == False:
        raise AddTraceError(addr, "Unable to a 'trace-breakpoint' at the given address.")
