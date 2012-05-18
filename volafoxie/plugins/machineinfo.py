
import volafoxie.commands as commands

class machineinfo(commands.Command):
    def GetOsVersion(self):
        data = self.volafoxie.os_info(self.symbol_list['_osversion'])
        output = '[+] Detail Darwin kernel version: %s\n'%data[0].strip('\x00')
        return output

    def GetMachineInfo(self):
        output = '\n[+] Mac OS X Basic Information\n'
        data = self.volafoxie.MachineInfo(self.symbol_list['_machine_info'])
        output += ' [-] Major Version: %d\n'%data[0]
        output += ' [-] Minor Version: %d\n'%data[1]
        output += ' [-] Number of Physical CPUs: %d\n'%data[2]
        output += ' [-] Size of memory in bytes: %d bytes\n'%data[3]
        output += ' [-] Size of physical memory: %d bytes\n'%data[4]
        output += ' [-] Number of physical CPUs now available: %d\n'%data[5]
        output += ' [-] Max number of physical CPUs now possible: %d\n'%data[6]
        output += ' [-] Number of logical CPUs now available: %d\n'%data[7]
        output += ' [-] Max number of logical CPUs now possible: %d\n'%data[8]
        return output
    
    def calculate(self):
        self.output = self.GetOsVersion()
        self.output += self.GetMachineInfo()
    
    def execute(self):
        print self.output