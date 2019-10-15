from ida_funcs import func_t, get_func, get_func_name

class IDAFunc(object):
    def __init__(self, addr):
        super(IDAFunc, self).__init__()
        self.func_t = get_func(addr)
        self.start_ea = self.func_t.start_ea
    
    def empty(self):
        return self.func_t.empty()

    def __repr__(self):
        try:
            func_name = get_func_name(self.func_t.start_ea)
        except:
            func_name = "<unknown>"

        return "<Func at 0x{:X}, name: {}>".format(self.func_t.start_ea, func_name)