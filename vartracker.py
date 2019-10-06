import idc
import idaapi 
import re
from aenum import Enum

from DDE.IDAHelpers.funcscope import  GetFuncStartAddr, GetFuncEndAddr

idaapi.require('arch64')
from arch64 import x64Regs, x32Regs, x16Regs, x8Regs, x64RegList, x32RegList, x16RegList, x8RegList

x64CommonRegs = [i.value for i in list(x64Regs) if i.value != x64Regs.RIP.value]


class Track(object):
    def __init__(self, operandSource, operandTarget):
        super(Track, self).__init__()
        self.operandSource = operandSource
        self.operandTarget = operandTarget
        self.children = []
    
    def __repr__(self):
        result = "<Track src: 0x{:X}, trg: 0x{:X}>".format(self.operandSource.instructionAddress)
        children = self.children
        deepness = 1
        while len(children) > 0:
            tab = ""
            for i in range(0, 1):
                tab = tab + " "
            
            for child in children:
                result = result + "\n"
                result = result + tab
                result = repr(children)
        
        return result

class OperandType(Enum):
    Register64 = 1
    Register32 = 2
    Register16 = 3
    Register8 = 4
    Value64OfRegisterPlusOffset = 5
    Value32OfRegisterPlusOffset = 6
    Value16OfRegisterPlusOffset = 7
    Value8OfRegisterPlusOffset = 8
    Immediate64 = 9
    Immediate32 = 10
    Immediate16 = 11
    Immediate8 = 12
    ImmediateUnkown = 13

class SizeModifier(Enum):
    Unknown = 0
    x64 = 1
    x32 = 2
    x16 = 3
    x8  = 4

class OperandStringParser(object):
    offsetRegexpStr = '\[(.*)\]'

    def __init__(self, opStr):
        super(OperandStringParser, self).__init__()
        self.opStr = opStr
    
    def getOperandType(self):
        sizeModifier = self.getSizeModifier()
        if self.hasOffset():
            if sizeModifier == SizeModifier.x64:
                return OperandType.Value64OfRegisterPlusOffset
            elif sizeModifier == SizeModifier.x32:
                return OperandType.Value32OfRegisterPlusOffset
            elif sizeModifier == SizeModifier.x16:
                return OperandType.Value16OfRegisterPlusOffset
            elif sizeModifier == SizeModifier.x8:
                return OperandType.Value8OfRegisterPlusOffset
            else:
                raise Exception("Unsupported operand type.")
        elif self.hasRegName():
            regName = self.getRegName()
            if regName in x64RegList:
                return OperandType.Register64
            elif regName in x32RegList:
                return OperandType.Register32
            elif regName in x16RegList:
                return OperandType.Register16
            elif regName in x8RegList:
                return OperandType.Register8
            else:
                raise Exception("Unsupported operand type.")
        else:
            return OperandType.ImmediateUnkown

    def getSizeModifier(self):
        if self.hasOffset():
            if "byte ptr" in self.opStr:
                return SizeModifier.x8
            elif "word ptr" in self.opStr:
                return SizeModifier.x16
            elif "dword ptr" in self.opStr:
                return SizeModifier.x32
            else:
                return SizeModifier.x64
        else:
            if self.opStr in x64RegList:
                return SizeModifier.x64
            elif self.opStr in x32RegList:
                return SizeModifier.x32
            elif self.opStr in x16RegList:
                return SizeModifier.x16
            elif self.opStr in x8RegList:
                return SizeModifier.x8
            else:
                # it means that it is an immediate value, like 0FFFFFFFFh
                return SizeModifier.Unknown

    def hasOffset(self):
        parts = self.getParts()
        if len(parts) > 1:
            return True
        return False
    
    def hasReg(self):
        return self.getRegName() != None
    
    def getRegName(self):
        parts = self.getParts()
        name = None
        if len(parts) > 0:
            if (parts[0] in x64RegList) or (parts[0] in x32RegList) or (parts[0] in x16RegList) or (parts[0] in x8RegList):
                name = parts[0]
        return name
    
    def getParts(self):
        matches = re.findall(self.offsetRegexpStr, self.opStr)
        if len(matches) == 0:
            return []

        return matches[0].split('+')

class Operand(object):
    def __init__(self, instructionAddress, operandIndex):
        super(Operand, self).__init__()
        self.instructionAddress = instructionAddress
        self.operandIndex = operandIndex
        self.value = None

        self.opStr = idc.GetOpnd(instructionAddress, operandIndex)
        self.opValue = idc.GetOperandValue(instructionAddress, operandIndex)
        # examples:
        # | Opnd                | Value        |
        # |---------------------|--------------|
        # | byte ptr [rax+1Ah]  | 0x1A         |
        # | word ptr [rax+1Ah]  | 0x1A         |
        # | dword ptr [rax+1Ah] | 0x1A         |
        # | [rax+TESForm.type]  | 0x1A         |
        # | [rsp+0B8h+var_80]   | 0x38         | # var_80 = -0x80
        # | [rax+1Ah]           | 0x1A         |
        # | [ecx-1]             | 0xffffffffL  |
        # | [rax]               | ???          |
        # | rcx                 | 1            |
        # | 2Fh                 | 0x2F         |

        self.parser = OperandStringParser(self.opStr)

    def readValue(self):
        if self.value != None:
            return self.value

        operandType = self.parser.getOperandType()
        regName = self.parser.getRegName()
        regValue = idc.GetRegValue(regName) if regName != None else None
        if operandType == OperandType.Value64OfRegisterPlusOffset:
            self.value = idc.Qword(regValue + self.opValue)
        elif operandType == OperandType.Value32OfRegisterPlusOffset:
            self.value = idc.Dword(regValue + self.opValue)
        elif operandType == OperandType.Value16OfRegisterPlusOffset:
            self.value = idc.Word(regValue + self.opValue)
        elif operandType == OperandType.Value8OfRegisterPlusOffset:
            self.value = idc.Byte(regValue + self.opValue)
        elif (operandType == OperandType.Register64) or (operandType == OperandType.Register32):
            self.value = regValue
        elif (operandType == OperandType.Register16) or (operandType == OperandType.Register8):
            self.value = regValue
        elif operandType == OperandType.ImmediateUnkown:
            self.value = self.opValue
        else:
            raise Exception("Unknown operand type")

        return self.value

class Instruction(object):
    def __init__(self, addr):
        super(Instruction, self).__init__()
        self.mnems = []
        self.addr = addr
    
    def canHandleMnemonics(self, mnemonics):
        if mnemonics in self.mnems:
            return True
        return False

class MovInstruction(Instruction):
    def __init__(self, addr = 0):
        super(MovInstruction, self).__init__(addr)
        self.mnems = ['mov']

    def getSourceValue(self):
        sourceOperand = self.getSourceOperand()
        if sourceOperand is None:
           return None

        return sourceOperand.readValue() 
    
    def getTargetValue(self):
        targetOperand = self.getTargetOperand()
        if targetOperand is None:
            return None

        return targetOperand.readValue()

    def getSourceOperand(self):
        if self.addr == 0:
            return None
        source = Operand(self.addr, 1)
    
    def getTargetOperand(self):
        if self.addr == 0:
            return None
        source = Operand(self.addr, 0)
        

class InstructionTracker(object):
    def __init__(self, instruction):
        super(InstructionTracker, self).__init__()
        self.instruction = instruction
    
    def getTrack(self):
        raise NotImplementedError()
    
class MovInstructionTracker(InstructionTracker):
    def __init__(self, instruction):
        super(MovInstructionTracker, self).__init__(instruction)
        if (type(instruction) != MovInstruction):
            raise Exception("Unsupported instruction type {}".format(instruction.__name__))
    
    def getTrack(self, valueToTrack):
        sourceValue = self.instruction.getSourceValue()
        if (sourceValue is None) or (sourceValue != valueToTrack):
            return None
        else:
            return Track(self.instruction.getSourceOperand(), self.instruction.getTargetOperand())

class InstructionTrackerFactory(object):
    def __init__(self):
        super(InstructionTrackerFactory, self).__init__()
        self.supportedTrackers = {
            MovInstruction: MovInstructionTracker
        }

    def getTrackerForInstruction(self, supportedInstruction):
        supportedTrackerCtor = self.supportedTrackers.get(type(supportedInstruction), None)
        if supportedTrackerCtor is None:
            return None
        return supportedTrackerCtor(supportedInstruction)

class TrackHistory(object):
    def __init__(self, name, valueToTrack):
        super(TrackHistory, self).__init__()
        self.name = name
        self.valueToTrack = valueToTrack
        self.historyRoots = []
        self.recentRoots = []
    
    def addTrack(self, newTrack):
        # TODO: rewrite using binary tree for faster match (key: targetOperand)
        
        print("Adding {}".format(repr(newTrack)))
        
        if not issubclass(newTrack, Track):
            raise Exception("Track history only holds subclusses of {}".format(Track.__name__))
        
        if len(self.historyRoots) == 0:
            self.historyRoots.append(newTrack)

        # shallow scan
        for track in self.recentRoots:
            if track.targetOperand.readValue() == newTrack.sourceOperand.readValue():
                track.children.append(track)
                self.recentRoots.remove(track)
                self.recentRoots.append(newTrack)
                return
        
        # deep scan
        for track in self.historyRoots:
            if self.__addTrack__(track, newTrack): return
        
        # parent isn't found, add it as a new root
        self.historyRoots.append(newTrack)

    def __addTrack__(self, track, newTrack):
        if track == None: return False

        if track.targetOperand.readValue() == newTrack.sourceOperand.readValue():
            track.children.append(newTrack)
            self.recentRoots.append(newTrack)
            return True
        
        if len(track.children) > 0:
            for childTrack in track.children:
                return self.__addTrack__(childTrack, newTrack)
        
        return False

class VarTracker(object):
    def __init__(self):
        super(VarTracker, self).__init__()
        self.trackHistories = {}
        self.rangeStart = 0
        self.rangeEnd = 0

        self.supportedInstructions = {
            "mov": MovInstruction
        }

        self.trackerFactory = InstructionTrackerFactory()
    
    def trackVariable(self, valueIdentifier, valueToTrack):
        trackHistory = self.trackHistories.get(valueIdentifier, None)
        if trackHistory is None:
            self.trackHistories[valueIdentifier] = TrackHistory(valueIdentifier, valueToTrack)
        else:
            raise Exception("Variable {} is already tracked. You can remove it from tracking by calling 'stopTracking' method", valueIdentifier)
    
    def trackVariables(self, variables):
        for v in variables:
            self.trackVariable(v[0], v[1])

    def stopTracking(self, valueIdentifier):
        trackHistory = self.trackHistories.get(valueIdentifier, None)
        if trackHistory is None:
            raise Exception("Variable {} isn't added to track. Add it first before removing.".format(valueIdentifier))
        else:
            del trackHistory[valueIdentifier]

    def setTracingRange(self, start, end):
        self.rangeStart = start
        self.rangeEnd = end

    def analyseStep(self):
        ripValue = idc.GetRegValue(x64Regs.RIP.value)
        instructionMnemonics = idc.GetMnem(ripValue)

        for valueIdentifier in self.trackHistories:
            instruction = self.supportedInstructions.get(instructionMnemonics, None)
            if instruction is None:
                return

            tracker = self.trackerFactory.getTrackerForInstruction(instruction(ripValue))
            if tracker is None:
                raise Exception("Tracker is not registered for the instruction {}".format(type(instruction).__name__))

            trackHistory = self.trackHistories.get(valueIdentifier, None)

            track = tracker.getTrack(trackHistory.valueToTrack)
            if track is None:
                continue
            trackHistory.addTrack(track)
    
    def beginAnalysis(self):
        if (self.rangeStart == 0) or (self.rangeEnd == 0):
            activeFuncScopeAddr = idc.ScreenEA()

            self.rangeStart = activeFuncScopeAddr
            self.rangeEnd = GetFuncEndAddr(activeFuncScopeAddr)

        # begin automatic debugging
        while idc.GetRegValue(x64Regs.RIP.value) != self.rangeEnd:
            idaapi.step_into()
            idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
            self.analyseStep()