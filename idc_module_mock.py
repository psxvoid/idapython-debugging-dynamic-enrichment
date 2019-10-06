import sys
import types

from unittest.mock import Mock

idc = types.ModuleType('idc')
sys.modules['idc'] = idc
idc.GetDebuggerEvent = Mock(name='idc.GetDebuggerEvent')
idc.BREAKPOINT = Mock(name='idc.BREAKPOINT')

idaapi = types.ModuleType('idaapi')
sys.modules['idaapi'] = idaapi
idaapi.run_requests = Mock(name='idaapi.run_requests')
idaapi.BADADDR = Mock(name='idaapi.BADADDR')
idaapi.GetRegValue = Mock(name='idaapi.GetRegValue')
idaapi.GetDisasm = Mock(name='idaapi.GetDisasm')
idaapi.run_requests = Mock(name='idaapi.run_requests')
idaapi.DBG_Hooks = Mock(name='idaapi.DBG_Hooks')
