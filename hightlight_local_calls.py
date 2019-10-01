import idaapi
import idc
import idautils

# define functions to do the jumping
def GetFuncStartAddr(addr):
    return idc.GetFunctionAttr(addr, idc.FUNCATTR_START)

def GetFuncEndAddr(addr):
    return idc.PrevHead(idc.GetFunctionAttr(addr, idc.FUNCATTR_END))

def GetAskForAddressResult():
    tgtEA = idc.AskAddr(0, "Enter target address")
    if tgtEA is None:
        exit
    return tgtEA

funcContainingAddr = idc.ScreenEA() #GetAskForAddressResult()
start_addr = GetFuncStartAddr(funcContainingAddr)
end_addr = GetFuncEndAddr(funcContainingAddr)
colour = 0xAAFF77

def rgb_to_bgr_color(rgb_hex_color):
    """
    Return color in 0xBBGGRR format used by IDA from standard 0xRRGGBB hexadecimal color value.
    """
    r = rgb_hex_color & 0xFF0000
    g = rgb_hex_color & 0x00FF00
    b = rgb_hex_color & 0x0000FF
    return (b << 16) | g | (r >> 16)

def MySetColor(ea, rgb_color):
    """ Set RGB color of one instruction or data at ea. """
    # SetColor does not return success or failure
    idc.SetColor(ea, idc.CIC_ITEM, rgb_to_bgr_color(rgb_color))

if (start_addr is None) or (end_addr is None):
  print "No basic block found that contains %X" % funcContainingAddr
else:
  print "found: %X - %X" % (start_addr, end_addr)


functionName = idc.GetFunctionName(start_addr)
for (startea, endea) in idautils.Chunks(start_addr):
    for head in idautils.Heads(startea, endea):
        #print functionName, ":", "0x%08x"%(head), ":", GetDisasm(head)
        if  idc.GetMnem(head) == 'call':
            MySetColor(head, colour)
            print "hightligting: %X" % (head)
        

# for i in range(start_addr, end_addr + 1, 8):
#     if  idc.GetMnem(i) == 'call':
#         MySetColor(i, colour)
#         print "hightligting: %X" % (i)