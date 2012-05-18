
import volafoxie.commands as commands

class syscallinfo(commands.Command):
    def GetSyscallInfo(self):
        data_list = self.volafoxie.syscall_info(self.symbol_list['_nsysent'])
        output = '\n-= syscall list =-\n'
        output += "{:<3} {:<4} {:<4} {:<5} {:<19} {:<19} {:<3} {:<9} {:<15} {:<30}\n".format(
            'num', 'narg', 'resv', 'flags', 'arg_munge32_ptr', 'arg_munge64_ptr', 'ret', 'arg_bytes', 'Address Type', 'call_ptr',)
        #print 'number        sy_narg        sy_resv        sy_flags        sy_call_ptr        sy_arg_munge32_ptr        sy_arg_munge64_ptr        sy_ret_type        sy_arg_bytes        Valid Function Address'
        for (count, data) in enumerate(data_list):
            output += "{count:<3} {0[0]:<4} {0[1]:<4} {0[2]:<5} {0[4]:<#19x} {0[5]:<#19x} {0[6]:<3} {0[7]:<9} ".format(data, count=count)
            call_ptr = [name for name, addr in self.symbol_list.iteritems() if addr == data[3]]
            if len(call_ptr) > 0:
                output += "{:<15} {:<30}".format("valid function", call_ptr[0])
            else:
                output += "{:<15} {:<#19x}".format("syscall hooking", data[3])
            output += '\n'
        return output
    
    def calculate(self):
        self.output = self.GetSyscallInfo()
        
    def execute(self):
        print self.output