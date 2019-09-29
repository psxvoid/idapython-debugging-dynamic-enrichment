from abc import ABCMeta, abstractmethod

class AnalyserBase(object):
    __metaclass__ = ABCMeta
    def __init__(self, *args, **kwargs):
        super(AnalyserBase, self).__init__(*args, **kwargs)
        self.scanMessage = "<None>"
    
    @abstractmethod
    def getMatch(self, addr):
        return False

    def getScanMessage(self):
        return self.scanMessage