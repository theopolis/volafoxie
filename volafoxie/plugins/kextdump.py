
import volafoxie.commands as commands

class kextdump(commands.Command):
    def __init__(self, kext):
        self.kext = kext
        pass
    
    def execute(self):
        data_list = self.volafoxie.kext_info(self.symbol_list['_kmod'])
        for data in data_list:
            if data[2] is not self.kext:
                continue
            print 'find kext, offset: %x, size: %x'%(data[7], data[8])
            self.volafoxie.kextdump(data[7], data[8], data[3].replace('\x00', '')) # addr, size, name
        pass