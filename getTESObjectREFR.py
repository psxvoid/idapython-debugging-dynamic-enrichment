import idc
import idaapi

# import tes_object_refr_functions

# insures that the module is reloaded
idaapi.require('tes_object_refr_functions')

addr = idc.AskAddr(0, "Enter address of TESObjectREFR")
if addr is None:
    exit()

tor = tes_object_refr_functions.TESObjectREFR(addr)

print("Items Count: %s" % tor.InventoryItems.Items.Count)
print("Elements Count: %s" % len(tor.InventoryItems.Items.Entries))