# -*- coding: utf-8 -*-

"""
  TODO
"""

import ctypes


# extra types
c_socklen_t = ctypes.c_uint


# classes

class iovec(ctypes.Structure):
  _fields_ = [
    ("iov_base", ctypes.c_void_p),
    ("iov_len", ctypes.c_ulong)
  ]


class msghdr(ctypes.Structure):
  """
    ref, https://ivanzz1001.github.io/records/post/linux/2017/11/04/linux-msghdr
  """
  _fields_ = [
    ("msg_name", ctypes.c_void_p),
    ("msg_namelen", c_socklen_t),
    ("msg_iov", ctypes.POINTER(iovec)),
    ("msg_iovlen", ctypes.c_size_t),
    ("msg_control", ctypes.c_void_p),
    ("msg_controllen", ctypes.c_size_t),
    ("msg_flags", ctypes.c_int)
  ]


class user_regs_structX64(ctypes.Structure):
  """
    grep "struct user_regs_struct" /usr/include/sys/user.h
  """
  _fields_ = [
    ("r15", ctypes.c_ulonglong),
    ("r14", ctypes.c_ulonglong),
    ("r13", ctypes.c_ulonglong),
    ("r12", ctypes.c_ulonglong),
    ("rbp", ctypes.c_ulonglong),
    ("rbx", ctypes.c_ulonglong),
    ("r11", ctypes.c_ulonglong),
    ("r10", ctypes.c_ulonglong),
    ("r9", ctypes.c_ulonglong),
    ("r8", ctypes.c_ulonglong),
    ("rax", ctypes.c_ulonglong),
    ("rcx", ctypes.c_ulonglong),
    ("rdx", ctypes.c_ulonglong),
    ("rsi", ctypes.c_ulonglong),
    ("rdi", ctypes.c_ulonglong),
    ("orig_rax", ctypes.c_ulonglong),
    ("rip", ctypes.c_ulonglong),
    ("cs", ctypes.c_ulonglong),
    ("eflags", ctypes.c_ulonglong),
    ("rsp", ctypes.c_ulonglong),
    ("ss", ctypes.c_ulonglong),
    ("fs_base", ctypes.c_ulonglong),
    ("gs_base", ctypes.c_ulonglong),
    ("ds", ctypes.c_ulonglong),
    ("es", ctypes.c_ulonglong),
    ("fs", ctypes.c_ulonglong),
    ("gs", ctypes.c_ulonglong),
  ]


class user_regs_struct(ctypes.Structure):
  """
    grep "struct user_regs_struct" /usr/include/sys/user.h
  """
  _fields_ = [
    ("ebx", ctypes.c_uint32),
    ("ecx", ctypes.c_uint32),
    ("edx", ctypes.c_uint32),
    ("esi", ctypes.c_uint32),
    ("edi", ctypes.c_uint32),
    ("ebp", ctypes.c_uint32),
    ("eax", ctypes.c_uint32),
    ("xds", ctypes.c_uint32),
    ("xes", ctypes.c_uint32),
    ("xfs", ctypes.c_uint32),
    ("xgs", ctypes.c_uint32),
    ("orig_eax", ctypes.c_uint32),
    ("eip", ctypes.c_uint32),
    ("xcs", ctypes.c_uint32),
    ("eflags", ctypes.c_uint32),
    ("esp", ctypes.c_uint32),
    ("xss", ctypes.c_uint32),
  ]


