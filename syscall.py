# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import errno
from collections import defaultdict
from typing import Any, List, Optional, Union, DefaultDict

from ptrace.syscall.ptrace_syscall import SYSCALL_NAMES
from prmsg import pr_msg

def str_to_int(s) -> Optional[int]:
    """
    Convert a string to an integer. Supports base 10 and hexadecimal numbers.

    Args:
        s (str): The input string.

    Returns:
        Optional[int]: The integer value of the string, or None if conversion fails.
    """
    
    if not isinstance(s, str):
        return None
    if s.startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except:
        return None

def ret_to_err(ret: Union[str,int]) -> Optional[int]:
    """
    Convert a return value to an error code.

    Args:
        ret (any): The input return value.

    Returns:
        Optional[int]: The error code, or None if the conversion fails.
    """
    v:Optional[int] = None

    if isinstance(ret, int):
        v = ret
    else:
        v = str_to_int(ret)
        if v is None:
            return None

    assert(v is not None)

    if v < 0:
        return v
    if v > (1 << 64) - 1024:
        return -((1 << 64) - v)
    return None


class SyscallInfo:
    syscall_numbers:DefaultDict[str,List[int]] = defaultdict(list)

    @staticmethod
    def get_name(n:int) -> str:
        """
        Get the syscall name associated with a syscall number.

        Args:
            n (int): The syscall number.

        Returns:
            str: The syscall name.
        """
        if n is None:
            return None
        return SYSCALL_NAMES.get(n, str(n))

    @staticmethod
    def get_syscall_nr(syscall:str) -> int:
        """
        Get the syscall number associated with a syscall name or number string.

        Args:
            syscall (str): The syscall name or number string.

        Returns:
            Optional[int]: The syscall number, or None if the syscall is not found.
        """
        if syscall is None:
            return None

        if syscall.isnumeric():
            return int(syscall)

        if len(SyscallInfo.syscall_numbers) == 0:
            SyscallInfo.syscall_numbers = defaultdict(list)
            for number, name in SYSCALL_NAMES.items():
                SyscallInfo.syscall_numbers[name.lower()].append(number)

        syscalls = SyscallInfo.syscall_numbers[syscall.lower()]
        if len(syscalls) > 1:
            pr_msg(f'Found multiple syscalls for {syscall}: {syscalls}; using {syscalls[0]}', level='WARN')
        elif len(syscalls) == 0:
            raise ValueError(f'Could not find syscall {syscall}')

        return syscalls[0]

class ErrorcodeInfo: 
    error_numbers:Optional[DefaultDict[str,List]] = None

    extra_error_codes = {
        512: 'ERESTARTSYS',
        513: 'ERESTARTNOINTR',
        514: 'ERESTARTNOHAND',
        515: 'ENOIOCTLCMD',
        516: 'ERESTART_RESTARTBLOCK',
        517: 'EPROBE_DEFER',
        518: 'EOPENSTALE',
        519: 'ENOPARAM',
        521: 'EBADHANDLE',
        522: 'ENOTSYNC',
        523: 'EBADCOOKIE',
        524: 'ENOTSUPP',
        525: 'ETOOSMALL',
        526: 'ESERVERFAULT',
        527: 'EBADTYPE',
        528: 'EJUKEBOX',
        529: 'EIOCBQUEUED',
        530: 'ERECALLCONFLICT',
        531: 'ENOGRACE'
    }

    @staticmethod
    def get_name(n:int) -> str:
        """
        Get the error string associated with an error code.

        Args:
            n (int): The error code.

        Returns:
            str: The error string.
        """
        if n is None:
            return None
        if n < 0:
            n = -n
        if n in errno.errorcode:
            return errno.errorcode[n]
        if n in ErrorcodeInfo.extra_error_codes:
            return ErrorcodeInfo.extra_error_codes[n]
        return str(n)

    @staticmethod
    def get_errno(err:str) -> Optional[int]:
        """
        Get the error code associated with an error string.

        Args:
            err (str): The error string.

        Returns:
            Optional[int]: The error code, or None if the error is not found.
        """
        if err is None or len(err) == 0:
            return None

        if err[0] == '-':
            err = err[1:]

        if err.isnumeric():
            return int(err)
        
        if err.startswith('0x'):
            return (1 << 64) - int(err, 16)

        # string
        if ErrorcodeInfo.error_numbers is None:
            ErrorcodeInfo.error_numbers = defaultdict(list)
            items = errno.errorcode.items() | ErrorcodeInfo.extra_error_codes.items()
            for number, name in items:
                ErrorcodeInfo.error_numbers[name.lower()].append(number)

        errnos = ErrorcodeInfo.error_numbers[err.lower()]
        if len(errnos) == 0:
            pr_msg(f'Could not find error {err}', level='ERROR')
            return None

        return errnos[0]

    @staticmethod
    def is_error_code(v: int, errcode: int) -> bool:
        """
            Check if a value matches an error code.

            Args:
                v (int): The value to check.
                errcode
            (int): The error code to compare.
        """
        if v < 0:
            v += 1 << 64

        mask32 = (1 << 32) - 1 
        v_low = v & mask32
        v_high = (v >> 32) & mask32
        return v_low == ((1 << 32) - errcode) and (v_high == mask32 or v_high == 0)