import idc
import idaapi

idaapi.require('debugger_dynamic_enrichment_hook')
# import debugger_dynamic_enrichment_hook

try:
    if debughook:
        if debughook.isInstalled:
            debughook.unhook()
except:
    pass

debughook = debugger_dynamic_enrichment_hook.MyDbgHook()
debughook.hook()

# Start debugging
idaapi.run_requests()