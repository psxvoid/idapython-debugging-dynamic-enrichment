class MemObject(object):
    def __init__(self, addr, deepness = 0):
        self.addr = addr
        self.deepness = deepness

    def __repr__(self):
        return "<MemObject at 0x{:X}>".format(self.addr)

    def __eq__(self, other):
        if isinstance(other, MemObject):
            return self.addr == other.addr
        return False

    def __ne__(self, other):
        result = self.__eq__(other)

class NullObject(object):
    def __init__(self, *args, **kwargs):
        super(NullObject, self).__init__(*args, **kwargs)

    def __repr__(self):
        return "NULL"

class ConditionalFormat(object):
    def __init__(self, value):
        super(ConditionalFormat, self).__init__()

        if type(value) == NullObject:
            self.format = "{}"
            self.repr = repr(value)
        elif issubclass(type(value), MemObject):
            self.format = "0x{:X}"
            self.repr = value.addr
        else:
            self.format = "0x{:X}"
            self.repr = value

    def __repr__(self):
        return "<ConditionalFormat format: %s, repr: %s>" % (self.format, self.repr)