import idaapi

def RVA(rva_addr):
    return idaapi.get_imagebase() + rva_addr