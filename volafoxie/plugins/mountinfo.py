
import volafoxie.commands as commands

class mountinfo(commands.Command):
    def GetMountInfo(self):
        data_list = self.volafoxie.mount_info(self.symbol_list['_mountlist'])
        output = '\n-= Mount List =-\n'
        # there should be a better way to do this...?
        sink_max = max([len(data[2].strip('\x00')) for data in data_list])
        source_max = max([len(data[3].strip('\x00')) for data in data_list])

        output += "{:<19} {:<10} {:<{sink_width}} {:<{source_width}}\n".format(
            'list entry-next', 'fstypename', 'mount on', 'mount from', sink_width=sink_max, source_width=source_max)
        for data in data_list:
            output += "{0[0]:<#19x} {0[1]:<10} {0[2]:<{sink_width}} {0[3]:<{source_width}}\n".format(
                [x.strip('\x00') if type(x) == str else x for x in data], sink_width=sink_max, source_width=source_max)    
        return output   
    
    def calculate(self):
        self.output = self.GetMountInfo()
    
    def execute(self):
        print self.output