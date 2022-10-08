# -*- coding: utf-8 -*-

"""
The module does implement a prototype of tracing functions using GDB python API:
    - NetBreakpoint class trace the function before the execution
    - NetFinishBreakpoint class trace the function after finishing the execution

If we want to add functions to trace follow ./docs/tracer_tutorial.md
"""



import gdb
import inspect
import config

from core.march import *
from tracer.lambda_rules import *
from utils.utilsX import *
from utils import hexdump


###       #
## Utils ##
#       ###

blacklist_bp = [
  "system","fork","execve","execl","execlp","execle",\
  "execv","execvp","execvpe"
]


def get_content(ptr, word, to_int=False) :
  return format_string_return(gdb.execute("x/" + word + "0x{:x}".format(ptr), to_string=True), to_int=True)


###         #
## Classes ##
#         ###

class TemplateBreakpoint :

  def __init__ (self, addr, fname, details):
    self.fname = fname
    self.addr = addr
    self.details = details
    self.__select_arch()
  
  def get_details(self, k) :
    return self.details[k]
  
  @property
  def arch(self) :
    return self.get_details("arch")
  
  @property
  def capsize(self) :
    return self.get_details("capsize")
  
  @property
  def word(self) :
    return self.get_details("word")
  
  @property
  def isa(self) :
    return self.get_details("isa")
  
  @property
  def running(self) :
    return self.get_details("running")
  
  def set_running(self) :
    self.details["running"] = True
  
  
  def __select_arch(self) :
    global ARCH_supported
    assert(self.arch in ARCH_supported)
    self.reg_args = archs[self.arch]['args']
    self.reg_ret_val = archs[self.arch]['ret_val']
    self.reg_ret = archs[self.arch]['ret']
  
  def get_arg(self, arg_range):
    output = []
    for i in range(arg_range) :
      output.append(
        int(gdb.parse_and_eval(self.reg_args[i]))
      )
    return output

  def get_ret(self):
    output = []
    output.append(int(gdb.parse_and_eval(self.reg_ret_val[0])))
    return output

  def hexdump_arg(self, n_arg=4, tail="[HIT]", print_ret=False):
    
    if "args" in dir(self) :
      args = self.args[:n_arg]
    else :
      args = self.get_arg(n_arg)
    output = []

    output.append(
      PTR['H2']("{}:0x{:x} ".format(self.fname, self.addr)) + tail
    )

    for i,x in enumerate(args):
      output.append(" \--->arg{}:".format(i) + PTR["L"]("0x{:x}".format(x)))
      try :
        output.append(hexdump.hexdump(x, config.hexdump_max_length))
      except :
        pass

    if print_ret :
      for i,x in enumerate(self.get_ret()) :
        output.append(" \--->ret{}:".format(i) + PTR["L"]("0x{:x}".format(x)))
        try :
          output.append(hexdump.hexdump(x, config.hexdump_max_length))
        except :
          pass

    self.details["slog"].append(
      "\n".join(output) + "\n"
    ) 

    return False



class NetFinishBreakpoint (gdb.FinishBreakpoint, TemplateBreakpoint) :

  def __init__ (self, addr, fname, details, args):
    gdb.FinishBreakpoint.__init__(self, gdb.newest_frame(), internal=True)
    TemplateBreakpoint.__init__ (self, addr, fname, details)
    self.silent = True 
    self.args = args

  def stop(self):
    global bp_map
    if self.fname in bp_map :
      bp_map[self.fname](self)
    else :
      self.hexdump_arg(tail="[RET]", print_ret=True)

    NetBreakpoint.post_rules.check(
      self.fname, self.args, self.get_ret()[0]
    )
    return False


class NetBreakpoint(gdb.Breakpoint, TemplateBreakpoint) :

  pre_rules = alertRules()
  post_rules = alertRules()

  def __init__(self, spec, addr, fname, details, trace_return=True):

    gdb.Breakpoint.__init__(
      self, spec, gdb.BP_BREAKPOINT, internal=True
    )
    TemplateBreakpoint.__init__ (self, addr, fname, details)
    self.spec = spec
    self.trace_return = trace_return


  def stop(self):
    global bp_map
    global blacklist_bp
    if not self.trace_return or self.fname in blacklist_bp :
      if self.fname in bp_map :
        bp_map[self.fname](self)
      else :
        self.hexdump_arg()

    else :
      n = 4
      args = self.get_arg(n)
      NetFinishBreakpoint(self.addr, self.fname, self.details, args)

    NetBreakpoint.pre_rules.check(self.fname, self.get_arg(4))
    return False


import tracer.extensions

bp_map = tracer.extensions.bp_map

