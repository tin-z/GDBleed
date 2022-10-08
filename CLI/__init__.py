# -*- coding: utf-8 -*-

"""
The module CLI will expose to GDB the new commands
"""

from CLI import general as general_mod
from CLI import memory as memory_mod
from CLI import hook as hook_mod
from CLI import bp_trace as bp_trace_mod
from CLI import store_load_state as store_load_state_mod



general = general_mod
memory = memory_mod
hook = hook_mod
bp_trace = bp_trace_mod
store_load_state = store_load_state_mod


def init(*args, **kwargs) :
  general.init(*args, **kwargs)
  memory.init(*args, **kwargs)
  hook.init(*args, **kwargs)
  bp_trace.init(*args, **kwargs)
  store_load_state.init(*args, **kwargs)



