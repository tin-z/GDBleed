# -*- coding: utf-8 -*-

"""
  Utils classes
"""
import re
from core import march
import threading

from config import slog_path

###       #
## utils ##
#       ###

slog_mutex = threading.Lock()

class simpleLogger :
  """
    Log class - singleton object where to save the output
  """

  singleton = False
  singleton_obj = None

  def __init__(self, fp=None):
    if simpleLogger.singleton :
      print("Can't create the class, because it already exists")

    simpleLogger.singleton = True
    simpleLogger.singleton_obj = self 

    self.is_stdout = True
    self.append_inner = self.print_to_stdout
    self.close = self.close_to_stdout

    if fp :
      self.fp = open(fp, "w")
      self.append_inner = self.prin_to_fp
      self.close = self.close_to_file
      self.is_stdout = False

  def append(self, out):
    global slog_mutex, cc
    slog_mutex.acquire()
    self.append_inner(out)
    slog_mutex.release()

  def print_to_fp(self, data):
    self.fp.write(data + "\n")

  def print_to_stdout(self, data):
    print(data)

  def close_to_stdout():
    pass

  def close_to_file():
    self.fp.close()

  def __del__(self):
    self.close()


slog = simpleLogger(fp=slog_path)


def format_string_return(data, to_int=False):
  rets = ":".join(data.split(":")[1:]).strip()
  if to_int :
    rets = int(rets, 16)
  return rets



valid_sep = ["d","u","x","s","n","p"]
valid_sep_dict = { "d":"p/d", "u":"p/u", "x":"p/x", "s":"x/s", "n":"p/x"}
valid_sep_regex = "^%[.]*\d*[$0-9]*[h]*({}).*".format("|".join(valid_sep))

"""
ref, https://cs155.stanford.edu/papers/formatstring-1.2.pdfu
parameter       output                                      passed as
    %d          decimal (int)                               value
    %u          unsigned decimal (unsigned int)             value
    %x          hexadecimal (unsigned int)                  value
    %s          string ((const) (unsigned) char *)          reference
    %n          number of bytes written so far, (* int)     reference
"""

def parse_format_string(str_fmt) :
  str_fmt = str_fmt.replace("\\\\", "[back-slash]").replace("\\%", "[back-slash-on-perc]")
  lst_fmt = str_fmt.split("%")
  counter = len(lst_fmt)
  output = []
  if len(lst_fmt) > 1 :
    for x in lst_fmt :
      x = "%" + x
      rets = re.match(valid_sep_regex, x)
      if rets :
        try :
          fmt_tmp = rets.group(1)
          output.append(valid_sep_dict[fmt_tmp])
        except Exception as ex :
          slog.append("[!] warning: bad exception at 'rets.group(1)' line in parse_format_string function. Input parse: '{}'".format(x))

      else :
        slog.append("[!] warning: can't resolve format string: {}".format(x))
  return output    

