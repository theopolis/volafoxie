
import volafoxie.commands as commands

class procinfo(commands.Command):
    def GetProcInfo(self):
        data_list = self.volafoxie.process_info(self.symbol_list['_kernproc'])
        output = '\n-= process list =-\n'
        output += "{:<20} {:>5} {:>5} {:<20} {:<20}\n".format('list_entry_next', 'pid', 'ppid', 'name', 'username')
        for data in data_list:
            output += "{0[0]:<#20x} {0[1]:>5} {0[4]:>5} {name:<20} {0[8]:<20}\n".format(data, name=data[6].split('\x00', 1)[0])
        return output
    
    def calculate(self):
        self.output = self.GetProcInfo()
        
    def execute(self):
        print self.output