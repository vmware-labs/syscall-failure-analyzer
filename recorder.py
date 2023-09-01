# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import logging
from typing import Optional, List, Dict, Any, Set, Iterable, Tuple, Union
import os
import pathlib
import pickle
import gzip
import io
import lz4.frame

from collections import defaultdict
import ptrace
import ptrace.debugger.child
import ptrace.debugger.process
import ptrace.syscall.ptrace_syscall
import ptrace.tools

from arch import arch
from angrmgr import Angr
from cle.backends import Symbol
from ftrace import Ftrace
from kallsyms import Kallsyms
from kcore import Kcore
from prmsg import pr_msg
from ptrace.syscall.ptrace_syscall import PtraceSyscall, SYSCALL_NAMES

class Recorder:
    def __init__(
        self,
        perf: str,
        output: str,
        kcore: 'Kcore',
        objs: List[io.BufferedReader],
        snapshot_size: int,
        syscall_filter: Optional[int],
        errcode_filter: Optional[int],
        occurrences_filter: Optional[Set[int]],
        debug: bool,
        save_kcore: bool,
        early_stop: bool,
    ):
        self.output = output
        self.failures: List[Dict] = []
        self.snapshot_size = max(snapshot_size, 128 * 1024)
        self.dbg = ptrace.debugger.debugger.PtraceDebugger()
        self.perf = perf
        self.syscall_filter = syscall_filter
        self.errcode_filter = errcode_filter
        self.occurrences_filter = occurrences_filter
        self.occurrences = 0
        self.debug = debug
        self.traces: List[Union[List[Dict[str, Union[int, str, float]]], str]] = []
        self.save_kcore = save_kcore
        self.early_stop = early_stop

        pr_msg('init kallsyms...', level='OP')
        self.rename_old_res_file(self.output)
        
        self.angr_mgr: Optional[Angr] = None
        self.kallsyms: Optional[Kallsyms] = None

        if kcore is not None:
            self.kallsyms = Kallsyms(objs = objs)
            self.angr_mgr = Angr(kallsyms = self.kallsyms,
                                kcore = kcore,
                                saved_segs = None)

    def detach_all_processes(self):
        if self.dbg is None:
            return
        for p in self.dbg.list:
            p.detach()

    def save_failures(self, type_str:str):
        if len(self.failures) == 0:
            return

        pr_msg(f'saving {len(self.failures)} failures...', level='INFO')

        data:Dict[str, Any] = {
            'type': type_str,
            'failures': self.failures,
            'traces': self.traces,
        }

        if self.save_kcore:
            assert isinstance(self.angr_mgr, Angr)
            data.update({
                'kcore': self.angr_mgr.save(),
                'kallsyms': self.kallsyms,
            })

        try:
            with lz4.frame.open(self.output, 'wb') as f:
                pickle.dump(data, f)
        except IOError:
            pr_msg("error writing to result file", level="ERROR")

    def set_sysexit_filter(self, ftrace_instance:Ftrace, snapshot:bool):
        e_class, e_subclass, filter = self.get_filter_string(exit=True)
        syscall_event = ftrace_instance.get_event(f'{e_class}/{e_subclass}')
        syscall_event.filter = filter
        if snapshot:
            syscall_event.trigger = f'snapshot if {filter}'
        return syscall_event

    def restart_syscall(self, process:ptrace.debugger.process.PtraceProcess, syscall:PtraceSyscall):
        rip = process.getInstrPointer()
        process.setInstrPointer(rip - arch.syscall_insn_len)
        process.setreg(arch.ret_reg_name, syscall.syscall)

    def print_syscall_info(self, syscall:PtraceSyscall):
        msg = f'syscall "{syscall.name}" ({syscall.syscall}) failed with error [{syscall.result_text}]'

        pr_msg(msg, level="INFO", new_line_before=True)
        syscall_args = [hex(arg.value) for arg in syscall.arguments]
        msg = 'failing syscall args: {0}'.format(', '.join(syscall_args))
        pr_msg(msg, level="INFO", new_line_after=True)

    def set_func_tracing(self, syms: Iterable[Symbol]) -> bool:
        ftrace = Ftrace.main_instance()

        # We cannot set function filters on cold symbols, and anyhow it is
        # meaningless, so ignore it silently.
        filter_sym_names = {sym.name for sym in syms if not sym.name.endswith('.cold')}
        success = True
        pr_msg(f'setting function filters ({len(filter_sym_names)} functions)...',
                level="OP")
        try:
            s = list(filter_sym_names) 
            ftrace.func_filter = s
            ftrace.current_tracer = 'function'
        except OSError as e:
            success = False
            pr_msg(f'cannot set function filter: {e}', level="ERROR", new_line_before=True)
        except Exception as e:
            success = False
            pr_msg(f'cannot set function filter: {e}', level="ERROR", new_line_before=True)

        return success

    def rename_old_res_file(self, output:str):
        res_file_path = pathlib.Path(output)
        if res_file_path.exists():
            try:
                res_file_path.rename(str(res_file_path)+".old")
            except Exception as e:
                pr_msg(f'error renaming result file {str(res_file_path)}',
                        level="FATAL")
                raise e


    def init_process(self, args:'list[str]'):
        args[0] = ptrace.tools.locateProgram(args[0])
        if not os.path.isfile(args[0]):
            raise FileNotFoundError(f"Error: file {args[0]} does not exist")
        if not os.access(args[0], os.X_OK):
            raise PermissionError(f'Error: file {args[0]} not executable')

        pid = ptrace.debugger.child.createChild(args, False, env=os.environ.copy())
        self.dbg.traceExec()
        self.dbg.traceClone()
        self.dbg.traceFork()
        self.dbg.addProcess(pid, is_attached=True)
        self.monitored_pid = pid

    def get_filter_string(self, exit:bool) -> Tuple[str, str, Optional[str]]:
        if exit:
            filter = 'ret<0' if self.errcode_filter is None else f'ret=={-self.errcode_filter}'
        else:
            filter = ''

        enter_or_exit = 'enter' if not exit else 'exit'

        e_class, e_subclass = 'raw_syscalls', f'sys_{enter_or_exit}'
        if self.syscall_filter is not None:
            syscall_name = SYSCALL_NAMES.get(self.syscall_filter, None)
            if syscall_name is not None:
                e_class, e_subclass = 'syscalls', f'sys_{enter_or_exit}_{syscall_name}'
            else:
                filter += f'&&id=={self.syscall_filter}'

        return e_class, e_subclass, filter if filter != '' else None