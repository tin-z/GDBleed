# -*- coding: utf-8 -*-

"""
Simple compiler strategies.

"""

import os
import config

tmp_folder = config.tmp_folder
LE = config.LITTLE_ENDIAN
BE = config.BIG_ENDIAN
compiler_path = config.compiler_path
compiler_flags = config.compiler_flags


class Compiler :
  """
    Compiler class

  """

  def __init__(self, details, details_mem, details_data) :
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data
    self.reset()

  def reset(self) :
    self.flags = compiler_flags[self.details["arch"]][self.details["endian"]]
    self.comp = compiler_path[self.details["arch"]][self.details["endian"]]

  def compile(self, file_name, code) :
    """
      - file_name : temporary file created
      - code : C code

      Return object file path. User should check the output file
    """
    object_file_name = file_name + ".o"
    in_file = "{}/{}".format(tmp_folder, file_name)
    out_file = "{}/{}".format(tmp_folder, object_file_name)
    
    with open(in_file, "w") as fp :
      fp.write(code)
 
    while True :
      cmd = "{} {} {} -o {}".format(self.comp, self.flags, in_file, out_file)
      os.system(cmd)

      self.details["slog"].append(
        "Code compiled or maybe not, you should check that and change stuff (folder '{}').\n".format(out_file) +\
        "Do you want to retry compilation? (y/Y/-)"
      )

      retry = input().strip()
      if retry.upper() != "Y" :
        break

    return out_file

