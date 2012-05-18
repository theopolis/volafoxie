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

class Command(object):
    output = ""
    
    def __init__(self):
        pass
    def start(self, instance=None, symbol_list={}):
        self.volafoxie = instance
        self.symbol_list = symbol_list
        self.calculate()
        pass
    def calculate(self):
        pass
    def execute(self):
        pass

