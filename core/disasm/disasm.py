# -*- coding: utf-8 -*-
from core.disasm.constants import TYP_CONDITIONAL_BRANCH
from core.disasm.disasm_strategy import R2Disasm


class WrapDisasm :
  
  supported_strategy = {
    "r2": R2Disasm
  }

  def __init__(self, details, details_mem, strategy="r2"):
    self.details = details
    self.details_mem = details_mem

    assert(strategy in WrapDisasm.supported_strategy)

    self.disasm = WrapDisasm.supported_strategy[strategy](
      self.details["binary_path"],
      self.details["is_pie"],
      self.details
    )
    self.baddr = self.disasm.baddr
    self.is_init = False


  def init(self):
    if self.is_init :
      return
    self.disasm.init()
    self.is_init = True

  def get_conditional_branches(self, jump_offset=None):
    bb_offsets = self.disasm.get_bbs(TYP_CONDITIONAL_BRANCH)
    bb_list = []

    for bb_offset in bb_offsets :
      bb_list.append(self.disasm.get_bb(bb_offset))

    rets = bb_list
    if jump_offset :
      for bb in bb_list :
        if bb.arg_offset == jump_offset :
          rets = [bb]
          break

    return rets


