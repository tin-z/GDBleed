# -*- coding: utf-8 -*-

"""
ELF GOT entries
"""

import lief

from utils.gdb_utils import get_data_memory, find_function_addr
 


class WrapPLTGOT :
  """
    Wrapper around plt-got LIEF object
  """

  def __init__(self, pltgot_lief, fname, address, address_dyn, decl, address_resolv) :
    """
      pltgot_lief : LIEF proxy object
      fname       : function name
      address     : got entry's offset
      address_dyn : got entry's virtual address
      decl        : call arguments types
      address_resolv : address of the function
    """
    self.pltgot_lief = pltgot_lief
    self.fname = fname
    self.address = address
    self.address_dyn = address_dyn
    self.decl = decl
    self.address_resolv = address_resolv
    self.address_hooking = -1

  def __str__(self):
    return self.pltgot_lief.__str__()

  def is_hooked(self):
    return self.address_hooking != -1


## Runtime methods

def got_symbols(binary_name, binary_name_local, base_address, size_base_address, details) :
  """
    The method extract got entries (only for the main binary, which is 
    the debugged process)

    Notes:
      - Simple plt.got support (MIPS' type of got is not supported)
      - Skip ordinal import

  """
  got_entries = dict()
  binary = lief.parse(binary_name_local)
  pltgot_list = binary.pltgot_relocations
  details["is_pie"] = binary.is_pie

  for x in pltgot_list :

    if x.has_symbol :
      address = x.address
      address_dyn = address 
      if details["is_pie"] :
        address_dyn += base_address 

      fname = x.symbol.name
      decl, address_resolv = find_function_addr(fname, details)

      # if dyn resolver already found function, then use that one
      rets = get_data_memory(details["word"], address_dyn)
      if rets < base_address or rets > (base_address + size_base_address) :
        address_resolv = rets

      y = WrapPLTGOT(x, fname, address, address_dyn, decl, address_resolv)
      got_entries.update({fname:y})

  return got_entries


