# IDA Python RTTI parser ~pod2g 06/2013

from idaapi import *
from idc import *

# TODO: test on 64bit !!!
addr_size = 4

first_seg = FirstSeg()
last_seg = FirstSeg()
for seg in Segments():
    if seg > last_seg:
        last_seg = seg
    if seg < first_seg:
        first_seg = seg

def get_pointer(ea):
    if addr_size == 4:
        return Dword(ea)
    else:
        return Qword(ea)

def in_image(ea):
    return ea >= first_seg and ea <= SegEnd(last_seg)

def get_class_name(name_addr):
    s = Demangle('??_7' + GetString(name_addr + 4) + '6B@', 8)
    if s != None:
        return s[0:len(s)-11]
    else:
        return GetString(name_addr)

start = first_seg
while True:
    f = FindBinary(start, SEARCH_DOWN, "2E 3F 41 56") # .?AV
    start = f + addr_size
    if f == BADADDR:
        break
    rtd = f - 8
    print "Found class: %s (rtd=0x%X)" % (get_class_name(f), rtd)
    for xref in XrefsTo(rtd):
        rchd = get_pointer(xref.frm + addr_size)
        if in_image(rchd):
            rcol = xref.frm - 12
            rchd_numBaseClasses = Dword(rchd + 8)
            rchd_pBaseClassArray = get_pointer(rchd + 12)
            for i in range(rchd_numBaseClasses):
                rbcd = get_pointer(rchd_pBaseClassArray + addr_size * i)
                rbcd_pTypeDescriptor = get_pointer(rbcd)
                rbcd_pTypeDescriptor_name = get_class_name(rbcd_pTypeDescriptor + 8)
                print "  - base class: %s" % rbcd_pTypeDescriptor_name
            for xref in XrefsTo(rcol):
                vtable = xref.frm + addr_size
                break
            print "  - vtable: 0x%X" % vtable
