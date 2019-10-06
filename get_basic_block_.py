# https://reverseengineering.stackexchange.com/questions/1646/how-to-map-an-arbitrary-address-to-its-corresponding-basic-block-in-ida
from bisect import bisect_right
import idaapi

# Wrapper to operate on sorted basic blocks.
class BBWrapper(object):
  def __init__(self, ea, bb):
    self.ea_ = ea
    self.bb_ = bb

  def get_bb(self):
    return self.bb_

  def __lt__(self, other):
    return self.ea_ < other.ea_

# Creates a basic block cache for all basic blocks in the given function.
class BBCache(object):
  def __init__(self, f):
    self.bb_cache_ = []
    for bb in idaapi.FlowChart(f):
      self.bb_cache_.append(BBWrapper(bb.startEA, bb))
    self.bb_cache_ = sorted(self.bb_cache_)

  def find_block(self, ea):
    i = bisect_right(self.bb_cache_, BBWrapper(ea, None))
    if i:
      return self.bb_cache_[i-1].get_bb()
    else:
      return None

def here():
    tgtEA = idaapi.askaddr(0, "Enter target address")
    if tgtEA is None:
        exit
    return tgtEA

bb_cache = BBCache(idaapi.get_func(here()))
found = bb_cache.find_block(here())
if found:
  print "found: %X - %X" % (found.startEA, found.endEA)
else:
  print "No basic block found that contains %X" % here()