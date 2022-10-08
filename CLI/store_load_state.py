# -*- coding: utf-8 -*-
import gdb
import pickle
from os.path import exists

from config import tmp_folder


default_store_file = "{}/state.bin".format(tmp_folder)


class StoreState(gdb.Command):
  
  """
    Save gdbleed session, which are stored in variables:
      - details
      - details_mem
      - details_data

  """
  
  default_cmd = "store-state"

  def __init__(self, name, details, details_mem, details_data, save_to=default_store_file):
    super(StoreState, self).__init__(name, gdb.COMMAND_NONE)
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data
    self.save_to = save_to

  def invoke(self, argv, from_tty):
    print("#TODO. Sorry not support right now, some issue  with pickle and lief modules")
    return

    try :
      fp = open(self.save_to, "wb")
      old_val = self.details["session_loaded"]
      self.details["session_loaded"] = True

      save_data = [self.details, self.details_mem, self.details_data]
      pickle.dump(save_data, fp)
      fp.close()

      self.details["session_loaded"] = old_val

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "[x] Can't save session into file '{}'".format(self.save_to)
      )



class LoadState(gdb.Command):
  
  """
    Load gdbleed session, which are stored in variables:
      - details
      - details_mem
      - details_data

  """
  
  default_cmd = "load-state"

  def __init__(self, name, details, details_mem, details_data, save_to=default_store_file):
    super(LoadState, self).__init__(name, gdb.COMMAND_NONE)
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data
    self.save_to = save_to
    self.skip_pid_check = False

  def invoke(self, argv, from_tty):
    print("#TODO. Sorry not support right now, some issue  with pickle and lief modules")
    return

    try :
      fp = fopen(self.save_to, "rb")
      save_data = pickle.load(fp)
      fp.close()
      self.update_state(save_data)
    except :
      self.details["slog"].append(
        "[x] Can't load session from file '{}'".format(self.save_to)
      )

  def update_state(self, save_data) :

    current_pid = self.details["pid"]
    new_pid = save_data[0]["pid"]

    if current_pid != new_pid :

      if self.skip_pid_check :
        return

      self.details["slog"].append(
        "[!] The debugged process has '{}' PID, meanwhile the saved session has '{}' PID\n".format(current_pid, new_pid) +\
        " \---> Do you still want to load the old session? (y/Y/-)"
      )
      if input().strip().upper() != "Y" :
        return

    save_data_now = [self.details, self.details_mem, self.details_data]
    for i, dict_now in enumerate(save_data_now) :
      dict_new = save_data[i]
      for k in list(dict_now.keys()) :
        dict_now[k] = dict_new[k]


def init(details, details_mem, details_data, extra=dict()) :
    StoreState(StoreState.default_cmd, details, details_mem, details_data)
    loadstate_obj = LoadState(LoadState.default_cmd, details, details_mem, details_data)

    if exists(loadstate_obj.save_to) :
      old_val = loadstate_obj.skip_pid_check
      loadstate_obj.skip_pid_check = True
      loadstate_obj.invoke(None, None)
      loadstate_obj.skip_pid_check = old_val

