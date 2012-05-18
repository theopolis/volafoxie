
import volafoxie.commands as commands

class procdump(commands.Command):
    def __init__(self, pid):
        self.pid = pid
        pass
    
    def execute(self):
        self.volafoxie.vaddump(self.symbol_list['_kernproc'], self.pid)
        pass