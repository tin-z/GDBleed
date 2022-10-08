# -*- coding: utf-8 -*-

"""
ELF Sections parsed with lief module
"""

import lief
import re



## Classes

class WrapSection :
    """
        Section LIEF object wrapper
    """

    def __init__(self, section_lief, base_address) :
        """
            section_lief    : Section LIEF proxy object
            base_address    : Main binary base address
        """
        self.section_lief = section_lief 
        self.fname = self.section_lief.name
        self.offset = self.section_lief.offset
        self.address_dyn = self.offset + base_address

    def __str__(self):
        return self.section_lief.__str__()


class DynstrSection(WrapSection) :
    """
        .dynstr section class
    """
    def __init__(self, section_lief, base_address) :
        super(DynstrSection, self).__init__(section_lief, base_address)
        self.parse_symname(base_address)

    def parse_symname(self, base_address) :
        self.symname = dict()
        output_tmp = ""
        offset_tmp = self.offset
        for i, x in enumerate(self.section_lief.content.tolist()) :
            if x != 0 :
                output_tmp += chr(x)
            else :
                if output_tmp != "" :
                    self.symname.update({output_tmp : base_address + offset_tmp})
                output_tmp = ""
                offset_tmp = self.offset + i + 1



## Runtime methods

def elf_sections(binary_name, binary_name_local, base_address, details) :
    """
        Parse ELF sections
    """
    section_entries = dict()
    binary = lief.parse(binary_name_local)
    section_list = binary.sections
    for x in section_list :
        fname = x.name
        if ".dynstr" == fname :
            y = DynstrSection(x, base_address)
        else :
            y = WrapSection(x, base_address)
        section_entries.update({fname:y})
    return section_entries

