#!/usr/bin/python
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
# Volafoxie (rewrite of n0fate's Volafox)
# Copyright 2012 Teddy - teddy@prosauce.org
# Original Source: volafox
# Copyright by n0fate - rapfer@gmail.com, n0fate@live.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
@author:       Teddy
@license:      GNU General Public License 2.0 or later
@contact:      teddy@prosauce.org
@organization: pro Sauce
"""

import pdb # For the debugger
#import getopt
#import sys
#import math

#import binascii
#import macho_an # user-defined class -> n0fate
#from ia32_pml4 import * # user-defined class -> n0fate

#from imageinfo import * # user defined class > CL
import pickle # added by CL
import os
import struct

from volafoxie.x86 import IA32PagedMemoryPae
from volafoxie.macho import MachoAddressSpace, isMachoVolafoxCompatible #, is_universal_binary
import volafoxie.addrspace as addrspace
import volafoxie.imageinfo as imageinfo
import volafoxie.ia32_pml4 as ia32_pml4


###############################################################################
#
# Class: volafox() - 2010-09-30
# Description: This analysis module can support Intel X86 Architecture
#              We need to have more research time ;)
#
# Dependency: x86.py in Volatility Framework for VA to PA
#
###############################################################################
class Volafoxie():
    debug = False
    build_types = {
        '10A432': '10.6.0',
        '10D573': '10.6.3', 
        '10D578': '10.6.3',
        '10D572': '10.6.3',
        '10F659': '10.6.4',
        '10F616': '10.6.4',
        '10H574': '10.6.5',
        '10H575': '10.6.6',
        '10J869': '10.6.7',
        '10J3250': '10.6.7',
        '10K540': '10.6.8',
        '10K549': '10.6.8',
        '11A511': '10.7.0',
        '11826': '10.7.1',
        '11C74': '10.7.2',
        '11D50': '10.7.3',
        '11D50b': '10.7.3',
        'Darwin': 'Darwin'
    }
    
    def __init__(self, mempath, debug=False):
##        self.idlepdpt = pdpt
##        self.idlepml4 = pml4 ### 11.09.28 n0fate
        self.mempath = mempath
        self.debug = debug
        '''Set baseAddressSpace'''
        if isMachoVolafoxCompatible(self.mempath):
            self.membase = MachoAddressSpace(self.mempath) 
        else:
            self.membase = addrspace.FileAddressSpace(self.mempath)
        self.arch = 32 # architecture default is 32bit
        self.data_list = []
        self.kern_version = ''
        self.valid_format = False # invalid

    def GetKernelVersion(self): # return (valid format(bool), architecture(int), Kernel Version(str))
        f = self.mempath
        returnResult = imageinfo.imageInfo(f)
        
        difference, build, sixtyfourbit = returnResult.catfishSearch(f)
        if self.debug:
            print '[+] Get Memory Image Information'
            print " [-] Difference(Catfish Signature):", difference # Catfish offset
        
        '''Todo: why is this not stored as a bool?'''
        self.valid_format = False if bool(difference) else True # weird
        if self.debug:
            print " [-] %(diag)s Mac %(type)s Format" % {
                "diag": "Maybe" if bool(difference) else "Valid", 
                "type": "Memory Reader" if bool(difference) else "Linear File"
            }
            
        self.arch = 64 if bool(sixtyfourbit) else 32
        if self.debug:
            print " [-] %d-bit memory image" % (self.arch)

        self.kern_version = self.build_types[build] if build in self.build_types.keys() else 'NotFound'
        if self.debug:
            print " [-] Build Version in Memory: %s" % build
            print " [-] Kernel Version: %s" % self.kern_version
        
        return {"is_valid_format": self.valid_format, 
                "architecture": self.arch, 
                "kernel_version": self.kern_version}

    def SetArchitecture(self, arch_num):
        if arch_num not in [32, 64]:
            return False
        self.arch = arch_num
        return True
    
    def init_vatopa_x86_pae(self, pdpt, pml4): # 11.11.23 64bit suppport
        if self.mempath == '':
            return False

        self.idlepdpt = pdpt
        self.idlepml4 = pml4
        
        if self.arch == 32:
            self.x86_mem_pae = IA32PagedMemoryPae(self.membase, self.idlepdpt)
        else:
            self.x86_mem_pae = ia32_pml4.IA32PML4MemoryPae(self.membase, self.idlepml4)
        return True
    
    def sleep_time(self, sym_addr):
        sleep_time = self.x86_mem_pae.read(sym_addr, 4);
        data = struct.unpack('i', sleep_time)
        return data

    def wake_time(self, sym_addr):
        wake_time = self.x86_mem_pae.read(sym_addr, 4);
        data = struct.unpack('i', wake_time)
        return data   

    def os_info(self, sym_addr): # 11.11.23 64bit suppport
        os_version = self.x86_mem_pae.read(sym_addr, 10) # __DATA.__common _osversion
        data = struct.unpack('10s', os_version)
        return data

    def MachineInfo(self, sym_addr): # 11.11.23 64bit suppport
        machine_info = self.x86_mem_pae.read(sym_addr, 40); # __DATA.__common _machine_info
        data = struct.unpack('IIIIQIIII', machine_info)
        self.os_version = data[0] # 11.09.28
        return data

    def kernel_kext_info(self, sym_addr): # 11.11.23 64bit support
        def kernel_kext_info32(sym_addr):
            Kext = self.x86_mem_pae.read(sym_addr, 168); # .data _g_kernel_kmod_info
            data = struct.unpack('III64s64sIIIIIII', Kext)
            return data
        def kernel_kext_info64(sym_addr):
            Kext = self.x86_mem_pae.read(sym_addr, 196); # .data _g_kernel_kmod_info
            data = struct.unpack('=QII64s64sIQQQQQQ', Kext)
            return data
        
        data = kernel_kext_info32 if self.arch is 32 else kernel_kext_info64(sym_addr)
        return data

    def kext_info(self, sym_addr): # 11.11.23 64bit support
        #print 'symboladdr: %x'%sym_addr
        kext_list = []
        
        if self.arch is 32:
            kmod_ptr_len     = 4
            kmod_ptr_type    = 'I'
            kmod_info_len    = 168
            kmod_info_format = 'III64s64sIIIIIII'
        else:
            kmod_ptr_len     = 8
            kmod_ptr_type    = 'Q'
            kmod_info_len    = 196
            kmod_info_format = '=QII64s64sIQQQQQQ'

        kmod_ptr = struct.unpack(kmod_ptr_type, self.x86_mem_pae.read(sym_addr, kmod_ptr_len))
        
        while True:
            if kmod_ptr[0] == 0 or not self.x86_mem_pae.is_valid_address(kmod_ptr[0]):
                break
            kmod_info = struct.unpack(kmod_info_format, self.x86_mem_pae.read(kmod_ptr[0], kmod_info_len))
            kext_list.append(kmod_info)
            kmod_ptr = kmod_info

        return kext_list

    def kextdump(self, offset, size, kext_name):
        if not self.x86_mem_pae.is_valid_address(offset):
            print 'Invalid address offset'
            return
        print '[DUMP] FILENAME: %s-%x-%x'%(kext_name, offset, offset+size)

        padding_code = 0x00
        pk_padding = struct.pack('=B', padding_code)
        padding = pk_padding*0x1000

        kext_fp = open('%s-%x-%x'%(kext_name, offset, offset+size), 'wb')
        for kext_offset in range(offset, offset+size, 0x1000):
            
            if not(self.x86_mem_pae.is_valid_address(kext_offset)):
                kext_fp.write(padding)
                continue
            
            data = self.x86_mem_pae.read(kext_offset, 0x1000)
            if data is None:
                kext_fp.write(padding)
                continue
            kext_fp.write(data)
            
        kext_fp.close()
        print '[DUMP] Complete.'
        return
    
    def mount_info(self, sym_addr): # 11.11.23 64bit suppport(Lion)
        mount_list = []
        
        if self.arch is 32:
            mount_ptr_len     = 4
            mount_ptr_type    = 'I'
            mount_info_len    = 2212
            mount_info_format = '=I144x16s1024s1024s'
        else:
            mount_ptr_len     = 8
            mount_ptr_type    = 'Q'
            mount_info_len    = 2276
            mount_info_format = '=Q204x16s1024s1024s'
            
        mount_ptr = struct.unpack(mount_ptr_type, self.x86_mem_pae.read(sym_addr, mount_ptr_len))
        while True:
            if mount_ptr[0] == 0 or not self.x86_mem_pae.is_valid_address(mount_ptr[0]):
                break
            mount_info = struct.unpack(mount_info_format, self.x86_mem_pae.read(mount_ptr[0], mount_info_len))
            mount_list.append(mount_info)
            mount_ptr = mount_info
        
        return mount_list

    def process_info(self, sym_addr): # 11.11.23 64bit suppport
        proc_list = []
        
        if self.arch is 32:
            kproc_ptr_len   = 4
            kproc_ptr_type  = 'I'
            proclist_len    = 476
            proclist_format = '4xIIIII392xI52sI'
            if self.os_version >= 11:
                proclist_len    += 24
                proclist_format = '4xIIIII392x24xI52sI'
            pgrp_len        = 16
            pgrp_format     = 'IIII'
            session_len     = 283
            session_format  = 'IIIIIII255s'
        else:
            kproc_ptr_len   = 8
            kproc_ptr_type  = 'Q'
            proclist_len    = 760
            proclist_format = '8xQQQQI652xI52sQ'
            if self.os_version >= 11:
                proclist_len    = 752+24
                proclist_format = '=8xQQQQI668xI52sQ'
            pgrp_len        = 32
            pgrp_format     = '=QQQQ'
            session_len     = 303
            session_format  = '=IQQIQQQ255s'
            
        kproc_ptr = struct.unpack(kproc_ptr_type, self.x86_mem_pae.read(sym_addr, kproc_ptr_len))
        while True:
            if kproc_ptr[0] == 0 or not self.x86_mem_pae.is_valid_address(kproc_ptr[0]):
                break
            try:
                proclist = struct.unpack(proclist_format, self.x86_mem_pae.read(kproc_ptr[0], proclist_len))
                pgrp     = struct.unpack(pgrp_format,     self.x86_mem_pae.read(proclist[7],  pgrp_len))
                session  = struct.unpack(session_format,  self.x86_mem_pae.read(pgrp[3],      session_len))
                proclist += (str(session[7]).strip('\x00'), )
                proc_list.append(proclist)
                kproc_ptr = proclist
            except struct.error:
                break
            
        return proc_list

    def syscall_info(self, sym_addr): # 11.11.23 64bit support
        syscall_list = []
        
        if self.arch == 32:
            sysent_ptr_len = 4
            sysent_ptr_type = 'I'
            sysent_len = 24
            sysent_format = 'hbbIIIII'
        else:
            sysent_ptr_len = 8
            sysent_ptr_type = 'Q'
            sysent_len = 40
            sysent_format = 'hbbQQQII'
        
        sysent_ptr = struct.unpack(sysent_ptr_type, self.x86_mem_pae.read(sym_addr, sysent_ptr_len))
        sysent_addr = sym_addr - (sysent_ptr[0] * sysent_len) 
        
        for count in range(0, sysent_ptr[0]):
            sysent = struct.unpack(sysent_format, self.x86_mem_pae.read(sysent_addr + (count * sysent_len), sysent_len)) 
            syscall_list.append(sysent)

        return syscall_list

    def vaddump(self, sym_addr, pid):
        import sys
        print '\n-= process: %d=-'%pid
        print 'list_entry_next        pid        ppid        process name                username'
        
        if self.arch == 32:
            kproc_ptr_len = 4
            kproc_ptr_type = 'I'
            proc_len = 476
            proc_format = '=4xIIIII392xI52sI'    
            pgrp_len = 16
            pgrp_format = 'IIII'
            session_len = 283
            session_format = 'IIIIIII255s'
            task_info_len = 36
            task_info_format = '=12xIIIIII'
            vm_info_len = 162
            vm_info_format = '=12xIIQQIIIQ16xIII42xIIIIIIIII'
            vme_list_len = 40
            vme_list_format = '=IIQQ12xI'
            pmap_info_len = 100
            pmap_info_format = '=IQIIII56xQII'
            pmap_cr3_index = 6
            if self.os_version >= 11:
                proc_len = 476+24
                proc_format = '=4xIIIII392x24xI52sI'
                task_info_len = 32
                task_info_format = '=8xIIIIII'
                vm_info_len += 12
                vm_info_format = '=12xIIQQII8x4xIQ16xIII42xIIIIIIIII'
                vme_list_len = 52
                vme_list_format = '=IIQQ24xI'
                pmap_info_len = 12
                pmap_info_format = '=4xQ'
                pmap_cr3_index = 0
        else:
            kproc_ptr_len = 8
            kproc_ptr_type = 'Q'
            proc_len = 760
            proc_format = '=8xQQQQI652xI52sQ'
            pgrp_len = 32
            pgrp_format = '=QQQQ'
            session_len = 303
            session_format = '=IQQIQQQ255s'
            task_info_len = 64
            task_info_format = '=24xIII4xQQQ'
            vm_info_len = 178
            vm_info_format = '=16xQQQQIIQQ16xIII42xIIIIIIIII'
            vme_list_len = 56
            vme_list_format = '=QQQQ16xQ'
            pmap_info_len = 152
            pmap_info_format = '=QQ112xQQQ'
            pmap_cr3_index = 2
            if self.os_version >= 11:
                proc_len = 752+24
                proc_format = '=8xQQQQI668xI52sQ'
                task_info_len = 56
                task_info_format = '=16xIII4xQQQ'
                vm_info_len = 182+12
                vm_info_format = '=16xQQQQII16xQQ16xIII42xIIIIIIIII'
                vme_list_len = 80
                vme_list_format = '=QQQQ40xQ'
                pmap_info_len = 16
                pmap_info_format = '=8xQ'
                pmap_cr3_index = 0
            
        
        kproc_ptr = struct.unpack(kproc_ptr_type, self.x86_mem_pae.read(sym_addr, kproc_ptr_len))
        
        while True:
            proclist = struct.unpack(proc_format, self.x86_mem_pae.read(kproc_ptr[0], proc_len))
            kproc_ptr = proclist
            if proclist[1] is not pid:
                continue
            sys.stdout.write('%.8x        '%proclist[0]) # int
            sys.stdout.write('%d        '%proclist[1]) # int
            sys.stdout.write('%d        '%proclist[4]) # int
            sys.stdout.write('%s        '%proclist[6].split('\x00', 1)[0])
 
            process_name = proclist[6].split('\x00', 1)[0]
            pgrp = struct.unpack(pgrp_format, self.x86_mem_pae.read(proclist[7], pgrp_len))
            session = struct.unpack(session_format, self.x86_mem_pae.read(pgrp[3], session_len))
            sys.stdout.write('%s'%session[7].replace('\x00',''))
            sys.stdout.write('\n')
            
            print '[+] Gathering Process Information'
            task_info = struct.unpack(task_info_format, self.x86_mem_pae.read(proclist[2], task_info_len))
            vm_info = struct.unpack(vm_info_format, self.x86_mem_pae.read(task_info[3], vm_info_len))
        
            print ' [-] Virtual Address Start Point: 0x%x'%vm_info[2]
            print ' [-] Virtual Address End Point: 0x%x'%vm_info[3]
            print ' [-] Number of Entries: %d'%vm_info[4]
            
            vm_list = []
            print '[+] Generating Process Virtual Memory Maps'
            entry_next_ptr = vm_info[1]
            for data in range(0, vm_info[4]):
                vme_list = struct.unpack(vme_list_format, self.x86_mem_pae.read(entry_next_ptr, vme_list_len))
                vm_list.append([vme_list[2], vme_list[3]])
                
                permission = max_permission = ''
                perm_list = []
                perm = (vme_list[4] >> 7) & 0x003f
                for i in range(7): # not sure if you really mean 7
                    perm_list.append(perm & 1)
                    perm = perm >> 1
                permission += 'r' if perm_list[0] == 1 else '-'
                permission += 'w' if perm_list[1] == 1 else '-'
                permission += 'x' if perm_list[2] == 1 else '-'
                max_permission += 'r' if perm_list[3] == 1 else '-'
                max_permission += 'w' if perm_list[4] == 1 else '-'
                max_permission += 'x' if perm_list[5] == 1 else '-'
                print ' [-] Region from 0x%x to 0x%x (%s, max %s;)'%(vme_list[2], vme_list[3], permission, max_permission)
                entry_next_ptr = vme_list[1]
            if vm_info[6] == 0 or not self.x86_mem_pae.is_valid_address(vm_info[6]):
                exit(1) # ??
            
            pmap_info = struct.unpack(pmap_info_format, self.x86_mem_pae.read(vm_info[6], pmap_info_len))
            pm_cr3 = pmap_info[pmap_cr3_index]
            
            proc_pae = 0
            print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
            #base = MachoAddressSpace(self.mempath) if isMachoVolafoxCompatible(self.mempath) else FileAddressSpace(self.mempath)
            proc_pae = ia32_pml4.IA32PML4MemoryPae(self.membase, pm_cr3)
            
            print '[+] Process Dump Start'
            for vme_info in vm_list:
                nop_code = 0x00
                pk_nop_code = struct.pack('=B', nop_code)
                nop = pk_nop_code * 0x1000
                
                process_fp = open('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]), mode="wb")
                
                nop_flag = 0 # 11.10.11 n0fate test
                for i in range(vme_info[0], vme_info[1], 0x1000):
                    raw_data = 0x00
                    if not(proc_pae.is_valid_address(i)):
                        if nop_flag == 1:
                            raw_data = nop
                            process_fp.write(raw_data)
                        continue
                    raw_data = proc_pae.read(i, 0x1000)
                    if raw_data is None:
                        if nop_flag == 1:
                            raw_data = nop
                            process_fp.write(raw_data)
                        continue
                    process_fp.write(raw_data)
                    nop_flag = 1
                process_fp.close()
                size = os.path.getsize('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
                if size == 0:
                    os.remove('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
                else:
                    print ' [-] [DUMP] Image Name: %s-%x-%x'%(process_name, vme_info[0], vme_info[1])
            # end vm_list iteration
            print '[+] Process Dump End'
            return
        # end while loop
    # end vad dump

    # http://snipplr.com/view.php?codeview&id=14807
    def IntToDottedIP(self, intip):
        octet = ''
        for exp in [3,2,1,0]:
            octet = octet + str(intip / ( 256 ** exp )) + "."
            intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))
        
    # 2011.08.08
    # network information (inpcbinfo.hashbase, test code)
    # it can dump real network information. if rootkit has hiding technique.
    #################################################
    def net_info(self, sym_addr, pml4):
        network_list = []
        
        net_pae = ia32_pml4.IA32PML4MemoryPae(self.membase, pml4)
        if sym_addr == 0 or not net_pae.is_valid_address(sym_addr):
            return
        
        if self.arch == 32:
            inpcb_info_len = 40
            inpcb_info_format = '=IIIIII12xI'
            inpcb_len = 4
            inpcb_format = '=I'
            inpcb_start_offset = 16
            in_network_len = 112
            in_network_format = '>HH48xI36xI12xI'
        else:
            inpcb_info_len = 72
            inpcb_info_format = '=QQQQQQ16xQ'
            inpcb_len = 8
            inpcb_format = '=Q'
            inpcb_start_offset = 24
            in_network_len = 156
            in_network_format = '>HH80xQ36xI20xI'

        inpcb_info = struct.unpack(inpcb_info_format, net_pae.read(sym_addr, inpcb_info_len))
        if not net_pae.is_valid_address(inpcb_info[0]):
            return
        
        print 'ipi_count: %d' % inpcb_info[6]
        loop_count = inpcb_info[2]
        
        for offset_hashbase in range(0, loop_count):
            inpcb = struct.unpack(inpcb_format, 
                net_pae.read(inpcb_info[0] + (offset_hashbase * inpcb_len), inpcb_len))
            loop_addr = inpcb[0]
            if loop_addr == 0 or not net_pae.is_valid_address(loop_addr):
                continue
            
            in_network = struct.unpack(in_network_format, 
                net_pae.read(loop_addr + inpcb_start_offset, in_network_len))
            network = [
                in_network[2],
                self.IntToDottedIP(in_network[3]),
                self.IntToDottedIP(in_network[4]),
                in_network[1],
                in_network[0]]
            network_list.append(network)

        return network_list

    # 2011.08.30 test code(plist chain)
    #################################################
    def net_info_test(self, sym_addr, pml4):
        network_list = []
        net_pae = ia32_pml4.IA32PML4MemoryPae(self.membase, pml4)
        
        if sym_addr == 0 or not net_pae.is_valid_address(sym_addr):
            return
        
        if self.arch == 32:
            inpcb_info_len = 40
            inpcb_info_format = '=IIIIII12xI'
            in_network_len = 112
            in_network_format = '>HHI44xI36xI12xI'
            inpcb_start_offset = 16
        else:
            inpcb_info_len = 72
            inpcb_info_format = '=QQQQQQ16xQ'
            in_network_len = 160
            in_network_format = '>HHI80xQ36xI20xI'
            inpcb_start_offset = 24

        inpcb_info = struct.unpack(inpcb_info_format, net_pae.read(sym_addr, inpcb_info_len))
        if not net_pae.is_valid_address(inpcb_info[5]):
            return
        
        temp_ptr = inpcb_info[5]
        while net_pae.is_valid_address(temp_ptr):
            in_network = struct.unpack(in_network_format, net_pae.read(temp_ptr + inpcb_start_offset, in_network_len))
            
            network = [
                in_network[3],
                self.IntToDottedIP(in_network[4]),
                self.IntToDottedIP(in_network[5]),
                in_network[1],
                in_network[0]]
            
            network_list.append(network)
            temp_ptr = in_network[2]
            
        return network_list

def main():
    import argparse
    import sys 
    parser = argparse.ArgumentParser(
        description='volafoxie (Memory Analyzer for OS X), a rewrite of volafox by n0fate. ' +
        'Requirements: Physical memory image (linear format), overlay data (symbol list). ' +
        'Supported OS: Snow Leopard (10.6.x), Lion (10.7.x). ' + 
        'Supported Archs: x86, x86_64.',
        epilog='Without -x or -m volafoxie will print memory image information. ' + 
        'OS version, Machine info, Mount info, Kernel KEXT info, KEXT info, Process list, Syscall Info, Network Info.')
    output_parser = parser.add_mutually_exclusive_group()
    parser.add_argument('-v', '--verbose', help='Enable Verbose mode.')
    output_parser.add_argument('-x', '--pid', type=int, help='Dump process memory for pid.')
    output_parser.add_argument('-m', '--kext', type=int, help='Dump KEXT memory for kext num.')
    parser.add_argument('image', help='Memory Image to analyze.')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print "[+] ERROR:", "Could not open", args.image
        sys.exit(1)
    
    # Auto switching code for using overlays or original mach-o files.  We should autopickle
    # using the original file.
##    if is_universal_binary(file_image):
##        macho_file = macho_an.macho_an(file_image)
##        arch_count = macho_file.load()
##
##        ## 11.11.22 n0fate
##        if arch_num is not 32 and arch_num is not 64:
##            macho_file.close()
##            sys.exit()
##        elif arch_num is 32:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_I386)
##            symbol_list = macho_file.macho_getsymbol_x86(header[2], header[3])
##            macho_file.close()
##        elif arch_num is 64:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_X86_64)
##            symbol_list = macho_file.macho_getsymbol_x64(header[2], header[3])
##            macho_file.close()
##    else:
##        #Added by CL
##        f = open(file_image, 'rb')
##        symbol_list = pickle.load(f)
##        f.close()
##
    volafox = Volafoxie(args.image, debug=True)

    ## get kernel version, architecture ##
    image_data = volafox.GetKernelVersion()
    #valid_format = init_data[0] # bool
    #architecture = init_data[1] # integer
    #kernel_version = init_data[2] # string

    ## check to valid image format
    if not image_data["is_valid_format"]:
        print '[+] WARNING: Invalid Linear File Format'
        print '[+] WARNING: If you have image using MMR, Converting memory image to linear file format'
        sys.exit()

    ## set architecture
    if not volafox.SetArchitecture(image_data["architecture"]):
        print '[+] WARNING: Invalied Architecture Information'
        sys.exit()

    if image_data["kernel_version"] in ['Darwin', 'NotFound']:
        print '[+] WARNING: Wrong Memory Image'
        sys.exit()

    ## open overlay file
    #overlay_path = os.path.join(["overlays", "%s_%d.overlay" % (image_data["kernel_version"], image_data["architecture"])])
    overlay_path = 'volafoxie/plugins/overlays/%s_%d.overlay'%(image_data["kernel_version"], image_data["architecture"])

    try:
        overlay_fp = open(overlay_path, 'rb')
        symbol_list = pickle.load(overlay_fp)
        overlay_fp.close()
    except IOError:
        print '[+] WARNING: volafox can\'t open \'%s\''%overlay_path
        print '[+] WARNING: You can create overlay file running \'overlay_generator.py\''
        sys.exit()

    ## Setting Page Table Map
    if not volafox.init_vatopa_x86_pae(symbol_list['_IdlePDPT'], symbol_list['_IdlePML4']):
        print '[+]  WARNING: Memory Image Load Failed'
        sys.exit()

### 11.09.28 start n0fate
    ## Pre-loading Machine Information for storing Major Kernel Version
    ## It is used to code branch according to major kernel version
    print symbol_list['_machine_info']
    volafox.MachineInfo(symbol_list['_machine_info'])
### 11.09.28 end n0fate    

    if args.kext is not None:
        from volafoxie.plugins.kextdump import kextdump
        module = kextdump(kext=args.kext)
    if args.pid is not None:
        from volafoxie.plugins.procdump import procdump
        module = procdump(pid=args.pid)
    if not args.pid and not args.kext:
        from volafoxie.plugins.procinfo import procinfo
        module = procinfo()
    
    module.start(volafox, symbol_list=symbol_list)
    module.calculate()
    module.execute()


if __name__ == "__main__":
    main()
