# -*- coding: utf-8 -*-

"""
  Trace stuff using breakpoints
"""

import gdb
import re
import lief

from CLI.memory import MemCommand

from utils.gdb_utils import find_function_addr

from tracer.trace_all import NetBreakpoint



class TraceBP(MemCommand):
  """
    Trace using breakpoints
  """

  cmd_default = "trace-bp"

  def __init__(self, name, details, details_mem, details_data):
    super(TraceBP, self).__init__(name, details, details_mem)
    self.details_data = details_data
    self.bp_list = []


  def do_reset(self, argv, reset_all=False):
    """
      Clear breakpoints
    """
    for bp in self.bp_list :
        bp.delete()
    self.bp_list = []


  def invoke(self, argv, from_tty):
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]

    try:
      syscall = argv[0]
      break_on_symbol = False
      break_on_addr = False

      if syscall == "--help" :
        raise Exception("help invoked")

      elif syscall == "--reset" :
        return self.do_reset(argv[1:])

      elif syscall == "--internal" :
        print("#TODO")
        return

      elif syscall == "--address" :
        break_on_addr = True
        syscall = argv[1]

      elif syscall == "--symbol" :
        break_on_symbol = True
        syscall = argv[1]

      if syscall == "--trace-all" :
        for syscall, wrap_pltgot in self.details_data["got_entries"].items():
          addr = wrap_pltgot.address_resolv
          if addr != None :
            spec = "*0x{:x}".format(addr)
            self.bp_list.append(NetBreakpoint(spec, addr, syscall, self.details))
          else :
            print("[!] skipping '{}' trace".format(syscall))
     
      else : 

        if not break_on_addr :
          if syscall not in self.details_data["got_entries"]:
            raise Exception("Can't find '{}' in GOT entries".format(syscall))
          wrap_pltgot = self.details_data["got_entries"][syscall]
          addr = wrap_pltgot.address_resolv
        else :
          base = 16 if syscall.startswith("0x") else 10
          addr = int(syscall,base)

        if break_on_symbol :
          spec = syscall
          addr = 0

        elif addr != None :
          spec = "*0x{:x}".format(addr)

        else:
          raise Exception("Can't find '{}'".format(syscall))

        self.bp_list.append(NetBreakpoint(spec, addr, syscall, self.details))

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} [--reset|--trace-all|--symbol] <symbol[@got]> ".format(TraceBP.cmd_default) + "\n" +\
        "     --trace-all         : do the ltrace similar function to each function imported by binary (don't traverse shared libraries)\n" +\
        "     --reset             : delete breakpoints\n" +\
        "     --symbol            : do breakpoint on symbol instead of address, breaking on each call of that function and not only inside PLT section\n" +\
        "     --address           : do breakpoint on specific address\n" +\
        "     --help              : this message\n"
      )



def init(details, details_mem, details_data, extra=dict()) :
  """
    Initialize trace methods
  """
  TraceBP(TraceBP.cmd_default, details, details_mem, details_data)


