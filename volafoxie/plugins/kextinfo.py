
import volafoxie.commands as commands

class kextinfo(commands.Command):
    def GetKernelKextInfo(self):
        data = self.volafoxie.kernel_kext_info(self.symbol_list['_g_kernel_kmod_info'])
        output = '\n-= Kernel Extentions(Kext) =-\n'
        output += "{:<19} {:<4} {:<3} {:<40} {:<10} {:<4} {:<19} {:<19} {:<7} {:<7} {:<19} {:<19}\n".format(
            'kmod_info_ptr', 'iver', 'id', 'name', 'version', 'refs', 'reference_list', 'address_ptr', 'size', 'hdr_size', 'start_ptr', 'stop_ptr')
        #sys.stdout.write( 'kmod_info_ptr        info_version        id        name        version        reference_count        reference_list        address_ptr        size        hdr_size        start_ptr        stop_ptr')
        #sys.stdout.write('\n')

        output += "{0[0]:<#19x} {0[1]:<4} {0[2]:<3} {0[3]:<40} {0[4]:<10} {0[5]:<4} {0[6]:<#19x} {0[7]:<#19x} {0[8]:<7} {0[9]:<7} {0[10]:<#19x} {0[11]:<#19x}".format(
            [x.strip('\x00') if type(x) == str else x for x in data])
        return output

    def GetKextInfo(self):
        data_list = self.volafoxie.kext_info(self.symbol_list['_kmod'])
        output = '\n-= Kernel Extentions(Kext) =-\n'
        output += "{:<19} {:<4} {:<3} {:<40} {:<10} {:<4} {:<19} {:<19} {:<7} {:<7} {:<19} {:<19}\n".format(
            'kmod_info_ptr', 'iver', 'id', 'name', 'version', 'refs', 'reference_list', 'address_ptr', 'size', 'hdr_size', 'start_ptr', 'stop_ptr')
        #sys.stdout.write( 'kmod_info_ptr        info_version        id        name        version        reference_count        reference_list        address_ptr        size        hdr_size        start_ptr        stop_ptr')
        #sys.stdout.write('\n')

        for data in data_list:
            output += "{0[0]:<#19x} {0[1]:<4} {0[2]:<3} {0[3]:<40} {0[4]:<10} {0[5]:<4} {0[6]:<#19x} {0[7]:<#19x} {0[8]:<7} {0[9]:<7} {0[10]:<#19x} {0[11]:<#19x}\n".format(
                [x.strip('\x00') if type(x) == str else x for x in data])
        return output
    
    def calculate(self):
        self.output = self.GetKernelKextInfo()
        self.output += self.GetKextInfo()
    
    def execute(self):
        print self.output