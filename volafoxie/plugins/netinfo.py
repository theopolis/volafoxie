#!/usr/bin/python
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
# Volafoxie (rewrite of n0fate's Volafox)
# Copyright 2012 Teddy - teddy@prosauce.org
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

import volafoxie.commands as commands

class netinfo(commands.Command):
    def calculate(self):
        self.output = self.GetNetInfo()
        self.output += self.GetNetInfoTest()
        
    def GetNetInfo(self):
        output = '\n-= NETWORK INFORMATION (hashbase) =-\n'
        network_list = self.volafoxie.net_info(self.symbol_list['_tcbinfo'], self.symbol_list['_IdlePML4'])
        for network in network_list:
            output += '[TCP] Local Address: {0[1]}:{0[3]:<5}, Foreign Address: {0[2]}:{0[4]:<5}, flag: {0[0]:<#x}\n'.format(network)
            
        network_list = self.volafoxie.net_info(self.symbol_list['_udbinfo'], self.symbol_list['_IdlePML4'])
        for network in network_list:
            output += '[UDP] Local Address: {0[1]}:{0[3]:<5}, Foreign Address: {0[2]}:{0[4]:<5}, flag: {0[0]:<#x}\n'.format(network)
        return output

    def GetNetInfoTest(self):
        output = '\n-= NETWORK INFORMATION (plist) =-\n'
        network_list = self.volafoxie.net_info_test(self.symbol_list['_tcbinfo'], self.symbol_list['_IdlePML4'])
        for network in network_list:
            output += '[TCP] Local Address: {0[1]}:{0[3]:<5}, Foreign Address: {0[2]}:{0[4]:<5}, flag: {0[0]:<#x}\n'.format(network)
            
        network_list = self.volafoxie.net_info_test(self.symbol_list['_udbinfo'], self.symbol_list['_IdlePML4'])
        for network in network_list:
            output += '[UDP] Local Address: {0[1]}:{0[3]:<5}, Foreign Address: {0[2]}:{0[4]:<5}, flag: {0[0]:<#x}\n'.format(network)
        return output
    
    def execute(self):
        print self.output

    