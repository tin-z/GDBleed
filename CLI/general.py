# -*- coding: utf-8 -*-
import gdb

class GetUtil(gdb.Command):
  """
    Get python variables from gdb UI
  """

  def __init__(self, name, var_name, details, details_data, cast_to=lambda x, y: x):
    super(GetUtil, self).__init__(name, gdb.COMMAND_NONE)
    self.var_name = var_name
    self.cast_to = cast_to
    self.__details_data = details_data
    self.details = details

  def invoke(self, argv, from_tty):
    self.details["slog"].append(self.cast_to(self.__details_data[self.var_name], argv))



def cast_got_entries(got_entries, argv) :
    output = []
    output_list = []
    output_dict = {}

    argv = [ x.strip() for x in argv.split(" ") if x.strip() != ""]
    if len(argv) > 0 :

        rets = "Can't find got-symbol '{}'".format(argv[0])

        if argv[0] == "--count" :
            rets = str(len(got_entries.items()))

        else :
            try :
                addr = got_entries[argv[0]].address_dyn
                rets = "[0x{:x}] ---> {}".format(addr, argv[0])
            except :
                pass

        return rets

    for k,x in got_entries.items() :
        addr = x.address_dyn
        fname = x.fname
        output_list.append(addr)
        output_dict.update({addr:fname})

    output_list.sort()

    for addr in output_list :
        output.append("[0x{:x}] ---> {}".format(addr, output_dict[addr]))

    return "\n".join(output)


def init(details, details_mem, details_data, extra=dict()) :
  """
    Initialize general CLI methods
  """
  GetUtil("base-address", "base_address", details, details_data, lambda x, y : hex(x))
  GetUtil("binary-name", "binary_name", details, details_data)
  GetUtil("binary-name-local", "binary_name_local", details, details_data)
  GetUtil("got-entries", "got_entries", details, details_data, cast_got_entries)


