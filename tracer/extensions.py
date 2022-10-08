# -*- coding: utf-8 -*-

"""
  This module will include custom breakpoints

  Custom breakpoints might also include lambda rules which are used to alert if suspicious data is seen
"""

import gdb
import inspect
from tracer.trace_all import NetFinishBreakpoint, NetBreakpoint, get_content

from utils.utilsX import format_string_return
from utils.colorsX import *


### 
## Utils
#
def get_stuff(self, n_arg=1):
  """
    self      : l'object NetFinishBreakpoint o NetBreakpoint che ci ha chiamato
    n_arg     : quanti argomenti ci aspettiamo (per ora max 4)

    ritorna in ordine: 
      - nome funzione
      - lista argomenti
      - valore di ritorno
  """
  #fname = inspect.getframeinfo(inspect.currentframe().f_back).function
  fname = self.fname
  ret_value = None
  if isinstance(self, NetFinishBreakpoint) :
    args = self.args
    ret_value = self.get_ret()[0]
  else :
    args = self.get_arg(n_arg)
  return fname, args, ret_value


###
## Custom breakpoint methods 
#
# - from here we add custom breakpoints. we follow the rule 'fname' e.g. 'recv' to custom breakpoint on 'recv' calls

def _w_recv(self):
  """
      ssize_t recv(int sockfd, void *buf, size_t len, int flags);
  """
  fname, args, ret_value = get_stuff(self,4)
  #
  fd_t, buf_t, len_t, flags_t = args
  
  self.details["slog"].append(
    PTR['H2'](fname) +\
    "(sockfd:{}, buf:0x{:x}, len:{}, flags:{}) -> ret:{}\n".format(
      fd_t, buf_t, len_t, flags_t, ret_value
    ) +\
    " \---> buf:{}\n".format(
      format_string_return(gdb.execute("x/s 0x{:x}".format(buf_t), to_string=True))
    )
  )


def _w_recvmsg(self):
  """
      ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
  """
  fname, args, ret_value = get_stuff(self,3)
  #
  sockfd_t, msg_t, flags_t = args
  
  msg_iov = get_content(msg_t + (self.capsize * 2), self.word, to_int=True)
  iov_base = get_content(msg_iov, self.word, to_int=True)
  iov_len = get_content(msg_iov + self.capsize, self.word, to_int=True)
  
  rets_msg_iov = hexdump.hexdump(iov_base, config.hexdump_max_length)
  
  self.details["slog"].append(
      PTR['H2'](fname) +\
      "(sockfd:{}, msg:0x{:x}, flags:{}) -> ret:{}\n".format(
        sockfd_t, msg_t, flags_t, ret_value
      ) +\
      " \---> hexdump 'msg_iov' content at address 0x{:x}, 'iov_base' at address 0x{:x} :\n".format(
        msg_iov, iov_base
      ) +\
      "{}\n".format(rets_msg_iov)
  )


def _w_recvfrom(self):
  """
      ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen);
  """
  recv(self)


def _w_system(self):
  fname, args, ret_value = get_stuff(self,1)
  #
  command = args[0]
  self.details["slog"].append(
    PTR['H2'](fname) +\
    "(command:0x{:x})\n".format(command) +\
    " \---> command:{}\n".format(
      format_string_return(gdb.execute("x/s 0x{:x}".format(command), to_string=True))
    )
  )




##### Keep these lines at the end of the file as they are
def ex_func():
  pass

func_class = type(ex_func)

bp_map = {k.split("_w_")[1]:v for k,v in inspect.currentframe().f_locals.items() if k.startswith("_w_") and isinstance(v, func_class)}

