import idc
import idaapi

Appcall.proto("msvcrt___RTDynamicCast", "PVOID __fastcall __RTDynamicCast (PVOID inptr, LONG VfDelta, PVOID SrcType, PVOID TargetType, BOOL isReference);")(0,0,0,0,0)

# HMODULE __stdcall LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
load_library_a = a.proto("kernel32_LoadLibraryA", "HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)")
getprocaddr = a.proto("__imp__GetProcAddress@8", "int (__stdcall*GetProcAddress)(int hModule, LPCSTR lpProcName);")
def test_gpa():
    h = load_library_a("user32.dll")
    if h == 0:
        print "failed to load library!"
        return -1
    p = getprocaddr(h, "FindWindowA")
    if p == 0:
        print "failed to gpa!"
        return -2
    findwin = a.proto(p, "int FindWindow(LPCTSTR lpClassName, LPCTSTRlpWindowName);")
    hwnd = findwin("TIdaWindow", 0)
    idaapi.freelib(h)
    print "%x: ok!->hwnd=%x" % (p, hwnd)
    return 1
