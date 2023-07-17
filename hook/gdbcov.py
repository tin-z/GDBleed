# -*- coding: utf-8 -*-

"""
Inline hooking
"""

import hook
from hook.default_hooks import *


# from hook.core.disasm.disasm import WrapDisasm


class GDBCovTrampoline (GeneralHook) :
  """
    Code coverage trampoline point

  """

  def __init__(self, details, details_data, regs_) :
    fname = "write"
    self.str_unknown = "<unknown> \0".encode()
    self.str_emtpy = "\0\0\0\0".encode()
    self.str_new_line = "\n\0\0\0".encode()
    self.addr_str_unknown = hook.inject_data(self.str_unknown)
    self.addr_str_emtpy = hook.inject_data(self.str_emtpy)
    self.addr_str_new_line = hook.inject_data(self.str_new_line)
    super(GDBCovTrampoline, self).__init__(details, details_data, regs_, fname)
    self.__init_trampolines()


  def __init_trampolines(self) :
    pass
    # use strategy + factory



