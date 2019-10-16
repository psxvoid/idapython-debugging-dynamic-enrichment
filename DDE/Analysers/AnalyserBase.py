from abc import ABCMeta, abstractmethod

class AnalyserBase(object):
    __metaclass__ = ABCMeta
    override_list = {
        "horizontal": {
            "overriden_by": {},
            "overriden_by_all": [],
            "overrides_all": []
        }
    }
    def __init__(self, *args, **kwargs):
        super(AnalyserBase, self).__init__(*args, **kwargs)

    @abstractmethod
    def getMatches(self, addr):
        return []