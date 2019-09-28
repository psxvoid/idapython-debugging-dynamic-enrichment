import idc
import idaapi

idaapi.require('debugger_dynamic_enrichment_hook')
# import debugger_dynamic_enrichment_hook

try:
    if debughook:
        if debughook.isInstalled:
            debughook.unhook()
        else:
            debughook = debugger_dynamic_enrichment_hook.MyDbgHook()
            debughook.hook()

except:
    try:
        debughook = debugger_dynamic_enrichment_hook.MyDbgHook()
        debughook.hook()
    except Exception as e:
        print(e)
    pass


# Start debugging
idaapi.run_requests()