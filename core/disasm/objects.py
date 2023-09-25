from core.disasm.constants import *


class Node :
  def __init__(self, offset, offset_end, obj_ptr, type):
    self.id_ = offset
    self.offset = offset
    self.offset_end = offset_end
    self.obj_ptr = obj_ptr
    self.type = type

  def is_type(self, type) :
    return self.type == type



class Fb(Node):
  """
    Function block

  """

  def __init__(self, offset, offset_end, r2_object, fname, type=TYP_FUNC, bb=set(), edge_in=set(), edge_out=set()):
    """
      offset : Function block offset
      offset_end : Next function block offset
      r2_object : Dictionary returned by r2 for future use
      fname : function name
      type : Function type
      bb : basic block set
      edge_in : functions calling this function set
      edge_out : functions being called by this function set

    """
    self.fname = fname
    self.edge_in = edge_in.copy()
    self.edge_out = edge_out.copy()
    self.bb = bb.copy()
    super(Fb, self).__init__(offset, offset_end, r2_object, type)

  def add_bb(self, bb) :
    self.bb.add(bb)

  def add_edge_in(self, offset):
    self.edge_in.add(offset)

  def add_edge_out(self, offset):
    self.edge_out.add(offset)


class Bb(Node):
  """
    Basic block
  """

  def __init__(self, offset, offset_end, r2_object, fb_offset, type=TYP_END_FUNCTION, **kwargs) :
    """
      offset : Basic block offset
      offset_end : Next basic block offset
      r2_object : Dictionary returned by r2 for future use
      fb_offset : Function block offset
      type : Basic block type

    """
    assert(type in type_blocks)
    super(Bb, self).__init__(offset, offset_end, r2_object, type)
    self.fb_offset = fb_offset

    if self.type & (TYP_BRANCH | TYP_CONDITIONAL_BRANCH) :
      k = ["arg_offset", "arg_size", "arg_opcode", "arg_bytes", "arg_jump"]
      if self.type & TYP_CONDITIONAL_BRANCH :
        k.append("arg_fail")
        k.append("arg_fail_type")
        k.append("arg_fail_opcode")
        k.append("arg_fail_size")

      for x in k :
        setattr(self, x, kwargs[x])
      if self.type & TYP_CONDITIONAL_BRANCH :
        setattr(self, "arg_jump_type", self.arg_opcode.split(" ")[0])

  def __str__(self):
    rets = f"Bb[{hex(self.offset)}:{hex(self.offset_end)}, {self.type})]"

    if self.type & (TYP_BRANCH | TYP_CONDITIONAL_BRANCH) :
      rets += f"({hex(self.arg_offset)}, {hex(self.arg_size)}, {self.arg_opcode}, 0x{self.arg_bytes}, {hex(self.arg_jump)}"

      if self.type & TYP_CONDITIONAL_BRANCH :
        rets += f", {self.arg_jump_type}"
        rets += f", {hex(self.arg_fail)}: {self.arg_fail_opcode}"
        rets += f", {self.arg_fail_size}"
        rets += f", {self.arg_fail_type}"

      rets += ")"

    return rets


  def __repr__(self):
    return self.__str__()
 


class Cb(Node):
  """
    Call block (instruction)
  """

  def __init__(self, offset, offset_end, r2_object, target=-1, type=TYP_CALL) :
    """
      offset : Call instruction offset
      offset_end : Next instruction offset (for mips we need the next's next instruction)
      r2_object : Dictionary returned by r2 for future use
      target : Call destination offset, only available for numerical operand
      type : Call block type

    """
    super(Cb, self).__init__(offset, offset_end, r2_object, type)
    self.target = target
 


