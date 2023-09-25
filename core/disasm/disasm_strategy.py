import r2pipe
import re
import time

from core.disasm.objects import *
from core.disasm.constants import *


## Interface
class StrategyDisasm:
  """
    Disasm strategy interface

  """

  def init(self):
    """
      Init function defined by sub classes

    """
    pass


  def get_fbs(self, filter_type=-1):
    """
      Return list of function block having type equals to 'filter_type' 
      (Default filter_type=-1 for returning every Fb)

    """
    if filter_type == -1 :
      return list(self.fb_offset_dict.keys())
    output = []
    for x,i in self.fb_offset_dict.items() :
      if self.fb_list[i].is_type(filter_type) :
        output.append(x)
    return output

  def get_bbs(self, filter_type=-1):
    """
      Return list of basic block having type equals to 'filter_type' 
      (Default filter_type=-1 for returning every Bb)

    """
    if filter_type == -1 :
      return list(self.bb_offset_dict.keys())
    output = []
    for x,i in self.bb_offset_dict.items() :
      if self.bb_list[i].is_type(filter_type) :
        output.append(x)
    return output

  def get_cbs(self, filter_type=-1):
    """
      Return list of instruction calls (Call block) having type equals to 'filter_type' 
      (Default filter_type=-1 for returning every Cb)

    """
    if filter_type == -1 :
      return list(self.cb_offset_dict.keys())
    output = []
    for x,i in self.cb_offset_dict.items() :
      if self.cb_list[i].is_type(filter_type) :
        output.append(x)
    return output



class R2Disasm(r2pipe.open_sync.open, StrategyDisasm):

  def __init__(self, binary_name, is_pie, details):
    super(R2Disasm, self).__init__(binary_name, ['-B', str(0)])
    self.binary_name = binary_name
    self.is_pie = is_pie
    self.details = details
    self.baddr = 0
    self.arch = self.details["arch"]
    self.import_section_offset = 0
    self.import_section_offset_end = 0

    if self.arch == "x86-64" :
      self.cmd_search_call = "/adj call"
      self.import_section_name = ".plt"
    else :
      # note for mips we need to use import_section_name = ".MIPS.stubs"
      raise Exception(f"Arch '{self.arch}' TODO")

    self.is_init = False


  def init(self):
    if self.is_init :
      return
    self.cmd('aaa')
    self.__init_fb()
    self.__init_cb()
    self.is_init = True

  def exec_cmdj_retry(self, cmd, raise_ex=False, retry=2, t_sleep=0.1) :
    for _ in range(retry) :
      rets = self.cmdj(cmd)
      if rets != {} :
        return rets
      time.sleep(t_sleep)
    if raise_ex :
        raise Exception(f"No return data from '{cmd}'")

  def __init_fb(self):
    self.fb_offset_dict = {}
    self.fb_list = []
    self.bb_offset_dict = {}
    self.bb_list = []

    functions = self.exec_cmdj_retry('aflj', True)
    for x in functions :
      if x['type'] == "fcn" :
        offset = x['minbound']
        fb_arg = [
          offset ,\
          x['maxbound'],\
          x ,\
          x['name'] ,\
          TYP_FUNC ,\
          set() ,\
        ]

        if fb_arg[-3].startswith("sym.imp.") :
          fb_arg[-2] = TYP_FUNC_IMP

        # TODO: add edge_in and edge_out ('callrefs' for edge_out and 'callxrefs' for edge_in)
        basic_blocks = self.exec_cmdj_retry(f'afbj {offset}')
        for y in basic_blocks :
          bb_offset = y['addr']
          bb_arg = [
            bb_offset ,\
            bb_offset + y['size'] ,\
            y ,\
            offset ,\
            TYP_END_FUNCTION ,\
          ]

          bb_extra_arg = {}
          if 'jump' in y :
            bb_arg[-1], bb_extra_arg = self.return_type_branch(bb_offset)

          self.bb_offset_dict.update(
            {bb_offset : len(self.bb_list)}
          )

          bb_extra_arg["arch"] = self.details["arch"]

          self.bb_list.append(
            Bb(*bb_arg, **bb_extra_arg)
          )

          fb_arg[-1].add(bb_offset)

        self.fb_list.append(
          Fb(
            *fb_arg
          )
        )
        self.fb_offset_dict.update(
          {offset : len(self.fb_list)}
        )


  def __set_imp_section(self):
    sections = self.exec_cmdj_retry("iSj")
    for s in sections :
      if s['name'] == self.import_section_name :
        self.import_section_offset = s['vaddr']
        self.import_section_offset_end = s['vaddr'] + s['vsize']

  def offset_is_in_imp_section(self, offset):
    return (\
      offset >= self.import_section_offset and \
      offset < self.import_section_offset_end \
    )


  def __init_cb(self):
    self.cb_offset_dict = {}
    self.cb_list = []

    if not self.import_section_offset :
      self.__set_imp_section()
    assert(self.import_section_offset != 0)

    assert(
      self.import_section_offset <= \
      self.import_section_offset_end
    )

    call_blocks = self.exec_cmdj_retry(self.cmd_search_call)
    for x in call_blocks :
      cb_offset = x['offset']
      cb_arg = [
        cb_offset ,\
        cb_offset + x['len'] ,\
        x ,\
        -1 ,\
        TYP_CALL ,\
      ]

      code = x['code']

      if code.lower() != "syscall" :

        target = code.split(" ")[1]

        if target.startswith("0x") :
          cb_arg[-2] = int(target, 16)

          if self.offset_is_in_imp_section(cb_arg[-2]) :
            cb_arg[-1] = TYP_CALL_IMP

      self.cb_list.append(
        Cb(
          *cb_arg
        )
      )
      self.cb_offset_dict.update(
        {cb_offset : len(self.cb_list)}
      )


  def return_type_branch(self, bb_offset):
    asm = self.exec_cmdj_retry(f'pdbj @ {bb_offset}')
    # NOTE: last instruction should be the branch one (for mips is the second last one)
    asm = asm[-1]

    ret_type = TYP_UNKNOWN_TYPE_BRANCH
    ret_dict = {
      "arg_offset" : asm["offset"] ,\
      "arg_size" : asm["size"] ,\
      "arg_opcode" : asm["opcode"] ,\
      "arg_bytes" : asm["bytes"] ,\
    }

    if asm['type'] in ['jmp', 'cjmp', 'nop', 'cmov', 'call', 'mov'] :
      # known type is fine

      if asm['type'] in ['cjmp', 'jmp'] :
        ret_type = TYP_BRANCH
        ret_dict.update(
          {"arg_jump" : asm["jump"]}
        )

      if asm["type"] == "cjmp" :
        ret_type = TYP_CONDITIONAL_BRANCH
        ret_dict.update(
          {"arg_fail" : asm["offset"] + asm["size"]}
        )

        asm = self.exec_cmdj_retry(f"pdj 1 @ {ret_dict['arg_fail']}")
        asm = asm[-1]

        if asm["type"] == "invalid" :
          raise Exception(
            f"r2disasm: Can't disasseble instruction at offset {hex(ret_dict['arg_fail'])}, upgrade radare2"
          )

        ret_dict.update(
          {
            "arg_fail_type" : asm["type"] ,\
            "arg_fail_opcode" : asm["opcode"] ,\
            "arg_fail_size" : asm["size"]
          }
        )

    else :
      self.details["slog"].append(
        print(
          f"[!] Found a basic block with type unknown at offset '0x{asm['offset']:x}' '{asm['type']}'"
        )
      )

    return ret_type, ret_dict


  def get_fb(self, offset):
    return self.fb_list[ \
      self.fb_offset_dict[offset]
    ]

  def get_bb(self, offset):
    return self.bb_list[ \
      self.bb_offset_dict[offset]
    ]

  def get_cb(self, offset):
    return self.cb_list[ \
      self.cb_offset_dict[offset]
    ]


