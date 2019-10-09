from aenum import Enum, Constant

class x64Regs(Enum):
    RAX = 'RAX'
    RBX = 'RBX'
    RCX = 'RCX'
    RDX = 'RDX'
    RSI = 'RSI'
    RDI = 'RDI'
    RBP = 'RBP'
    RSP = 'RSP'
    R8 = 'R8'
    R9 = 'R9'
    R10 = 'R10'
    R11 = 'R11'
    R12 = 'R12'
    R13 = 'R13'
    R14 = 'R14'
    R15 = 'R15'
    # special
    RIP = 'RIP'

class x32Regs(Enum):
    EAX = 'eax'
    EBX = 'ebx'
    ECX = 'ecx'
    EDX = 'edx'
    ESI = 'esi'
    EDI = 'edi'
    EBP = 'ebp'
    ESP = 'esp'
    R8d = 'r8d'
    R9d = 'r9d'
    R10d = 'r10d'
    R11d = 'r11d'
    R12d = 'r12d'
    R13d = 'r13d'
    R14d = 'r14d'
    R15d = 'r15d'

class x16Regs(Enum):
    AX = 'ax'
    BX = 'bx'
    CX = 'cx'
    DX = 'dx'
    SI = 'si'
    DI = 'di'
    BP = 'bp'
    SP = 'sp'
    R8w = 'r8w'
    R9w = 'r9w'
    R10w = 'r10w'
    R11w = 'r11w'
    R12w = 'r12w'
    R13w = 'r13w'
    R14w = 'r14w'
    R15w = 'r15w'

class x8Regs(Enum):
    AL = 'al'
    BL = 'bl'
    CL = 'cl'
    DL = 'dl'
    SIL = 'sil'
    DIL = 'dil'
    BPL = 'bpl'
    SPL = 'spl'
    R8b = 'r8b'
    R9b = 'r9b'
    R10b = 'r10b'
    R11b = 'r11b'
    R12b = 'r12b'
    R13b = 'r13b'
    R14b = 'r14b'
    R15b = 'r15b'

class x64RegInfo(Constant):
    MaxValue = 9223372036854775808

x64RegList = [i.value for i in list(x64Regs)]
x32RegList = [i.value for i in list(x32Regs)]
x16RegList = [i.value for i in list(x16Regs)]
x8RegList = [i.value for i in list(x8Regs)]

x64RegCommonList = [i.value for i in list(x64Regs) if i.value != x64Regs.RIP.value]
