import ida_dbg

def isInMemoryRange(addr):
    try:
        return ida_dbg.is_debugger_memory(addr)
    except:
        return False