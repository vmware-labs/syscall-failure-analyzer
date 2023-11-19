# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import atexit
import bisect
import fcntl
import io
import logging
import os
import pathlib
import re
import struct
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, TextIO, Tuple, Union, Callable

from cle.backends import Symbol
from prmsg import Pbar, pr_msg
from arch import arch

# TODO: Get rid of kcore
from kcore import Kcore

class Ftrace:
    common_trace_pattern = (
            r'\s+(?P<proc>[\S]+)\s+' +
            r'(?P<pid>\-?\d+)\s+' +
            r'\[(?P<cpu>\d+)\]\s+' +
            r'(?P<time>[\d\.]+):\s+'
    )

    common_trace_regex = re.compile(common_trace_pattern)

    ftrace_syscall_exit_pattern = r'sys_(?P<syscall>\S+) \-\> (?P<err>\S+)'

    ftrace_syscall_exit_regex = re.compile(ftrace_syscall_exit_pattern)

    ftrace_syscall_enter_regex = re.compile(r'sys_enter\:\s' +
                                r'NR (?P<syscall_nr>\d+)\s+' +
                                r'\((?P<args>[\s\,0-9a-f]+)\)')

    ftrace_ret_regex = re.compile(r'r_0x' +
                                r'[0-9a-f]+\:\s*' +
                                r'\((?P<to_func>[^\+\s\)]+)' +
                                r'\+0x(?P<offset>[0-9a-f]+)' +
                                r'\/0x(?P<size>[0-9a-f]+\s+)' +
                                r'\<(?P<to_ip>[0-9a-f]+)\>\s+' +
                                r'\<\- ' +
                                r'(?P<from_func>[^\)]+)\s+' +
                                r'\<(?P<from_ip>[0-9a-f]+)\>\)\s+' +
                                r'(?P<vals>.*)$')

    ftrace_func_regex = re.compile(r'(?P<to_func>\S+)\s+' +
                                    r'\<(?P<to_ip>[0-9a-f]+)\>\s+' +
                                    r'\<\-' +
                                    r'(?P<from_func>\S+)\s+' +
                                    r'\<(?P<from_ip>[0-9a-f]+)\>' +
                                    r'$')

    ftrace_regex_common = (r'(?P<comm>.{16})\-' +
                        r'(?P<pid>\d+)\s*' + 
                        r'\[(?P<cpu>\d+)\]\s+' +
                        r'(?P<time>[\d\.]+):\s+')

    ftrace_raw_syscall_exit_regex = re.compile(r'sys_exit\:\s' +
                                r'NR (?P<syscall_nr>\d+)\s+\=\s+' +
                                r'(?P<err>[\-]?\d+)')

    ftrace_regex_payload = re.compile(ftrace_regex_common + r'(?P<payload>.*)')
    ftrace_probe_regex = re.compile(r'p_0x[0-9a-f]+\:\s*' +
                                r'\((?P<sym>[^\+\s\)]+)' +
                                r'\+0x(?P<offset>[0-9a-f]+)' +
                                r'\/0x(?P<size>[0-9a-f]+)\s+' + 
                                r'\<(?P<addr>[0-9a-f]+)\>' +
                                r'\) ' +
                                r'(?P<vals>.*)$')

    fork_regex = re.compile(r'sched_process_fork: comm=(?P<comm>.+) ' +
                            r'pid=(?P<pid>\d+) ' + 
                            r'child_comm=(?P<child_comm>.+) ' +
                            r'child_pid=(?P<child_pid>\d+)')

    callstack_regex = re.compile(r' \=\> (?P<sym>\S+) \<(?P<addr>[0-9a-f]+)\>')

    syscall_exit_pattern1 = r'\S+\sNR (?P<syscall_exit_nr>\d+) = \-(?P<err>\d+)'
    syscall_exit_pattern2 = r'syscalls:sys_exit_(?P<syscall_exit_name>\S+): (?P<err2>0x\S+)'

    err_exit_pattern = syscall_exit_pattern1+'|'+syscall_exit_pattern2
    err_exit_re_combined = re.compile(err_exit_pattern)
    err_exit_regex = re.compile(common_trace_pattern + '(' + err_exit_pattern + ')')

    syscall_enter_pattern1 = r'syscalls:sys_enter_(?P<syscall_enter_name>\w+):\s+(?P<syscall_args1>.+)'
    syscall_enter_pattern2 = r'raw_syscalls:sys_enter:\s*NR\s*(?P<syscall_enter_nr>\d+)\s*\((?P<arguments>[\da-fA-F,\s]*)\)'
    
    syscall_enter_pattern = r'(' + syscall_enter_pattern1 + r'|' + syscall_enter_pattern2 + r')'
    
    complete_exit_regex = re.compile(common_trace_pattern + err_exit_pattern)
    entry_exit_regex = re.compile(common_trace_pattern + '('+err_exit_pattern+'|'+syscall_enter_pattern+')')

    entry_regex = re.compile(common_trace_pattern + syscall_enter_pattern)
    #entry_exit_regex = re.compile(err_exit_re_combined.pattern+'|'+syscall_enter_pattern)

    blacklist_pattern = (r'0x(?P<start>[0-9a-f]+)\-' +
                         r'0x(?P<end>[0-9a-f]+)\s+' +
                         r'(?P<sym>\S*)')

    blacklist_regex = re.compile(blacklist_pattern)

    __instance:Optional['Ftrace'] = None

    # TODO: Add interface to get_sym() and use it instead of 

    @staticmethod 
    def main_instance(angr_mgr:Optional[Any] = None) -> 'Ftrace':
        """ Static access method. """
        if Ftrace.__instance is None:
            f = Ftrace()
        else:
            f = Ftrace.__instance
 
        if angr_mgr is not None:
            if f.__angr_mgr is None:
                f.__angr_mgr = angr_mgr
            assert f.__angr_mgr == angr_mgr
        
        return f

    @staticmethod
    def rmdir_instance(trace_path:pathlib.Path) -> bool:
        if not trace_path.exists():
            return True
        try:
            trace_path.rmdir()
        except Exception:
            return False

        return True

    def remove(self):
        if self.deleted:
            return

        for _, ev in self.events.items():
            ev.enable = False
        self.events = list()

        #self.tracing_on = False
        self.current_tracer = 'nop'
        self.kprobe_event_clear()
        self.disable_snapshot()
        if self.instance_name is not None:
            self.rmdir_instance(self.trace_path)
            main_instance = Ftrace.main_instance()
            del main_instance.instances[self.instance_name]
        self.trace_path = None
        self.deleted = True

    def __del__(self):
        self.remove()

    def __init__(self, instance_name:Optional[str] = None):
        self.cache:Dict[str, str] = dict()
        self.debug = False
        self.instances:Optional[Dict[str, 'Ftrace']] = None
        self.invalid_kprobe_addrs:Optional[List[int]] = None
        self.kprobe_cache:List[str] = list()
        self.kprobes_cleared = False
        self.kprobes_disabled = False
        #self.kprobes:Dict[Tuple[int, bool], 'Ftrace'.KprobeEvent] = dict()
        self.kprobes:Dict[str, 'Ftrace'.KprobeEvent] = dict()
        self.__available_funcs = None
        self.kprobe_event_file = None
        self.kprobe_blacklist:Optional[List[Tuple[int,int]]] = None
        self.events = dict()
        self.pipes:Dict[str,io.BufferedReader] = dict()
        self.deleted = False
        self.instance_name = instance_name
        self.clear_snaphot_executor = None
        self.__angr_mgr = None

        atexit.register(self.remove)

        """ For the main instance, we do not want to be able to create new instances"""
        if instance_name is None:
            if Ftrace.__instance is not None:
                raise Exception("This class is a singleton!")
            else:
                Ftrace.__instance = self
        else:
            main_instance = Ftrace.main_instance()

            assert main_instance.instances is not None

            if instance_name in main_instance.instances:
                raise Exception("This instance already exists!")
            main_instance.instances[instance_name] = self

        trace_path = pathlib.Path("/sys/kernel/debug/tracing")

        # Check that we got permission for ftrace
        try:
            trace_path.stat()
        except:
            raise Exception("cannot access ftrace")

        if instance_name is None:
            self.instances = dict()
        else:
            instances_path = trace_path.joinpath("instances")
            if not instances_path.exists():
                raise Exception("ftrace instance path does not exist")
            
            trace_path = instances_path.joinpath(instance_name)
            if not self.rmdir_instance(trace_path):
                raise Exception("ftrace instance directory in use")

            trace_path.mkdir()

        self.trace_path = trace_path

        self.__init_kprobes()
        if instance_name is None:
            self.kprobe_event_clear()

        self.__read_available_tracers()
    
    def init_kprobe_base(self, kprobe_base_sym_name:str, get_addr_fn:Callable[[str], Optional[int]]):
        self.kprobe_base_sym_name = kprobe_base_sym_name
        #self.kprobe_base_sym_addr = get_addr_fn(kprobe_base_sym_name)
        self.sym_addrs = dict()
        for sym in ['__start___jump_table',
                    '__stop___jump_table',
                    '__start_static_call_sites',
                    '__stop_static_call_sites',
                    kprobe_base_sym_name]:
            try:
                self.sym_addrs[sym] = get_addr_fn(sym)
            except ValueError as e:
                self.sym_addrs[sym] = None
        self.read_invalid_kprobe_addrs()

    def get_instance(self, instance_name:str):
        if self.instances is None:
            raise Exception("cannot create ftrace instance from non-main instance")
        if instance_name not in self.instances:
            try:
                self.instances[instance_name] = Ftrace(instance_name = instance_name)
            except Exception:
                raise Exception("cannot create ftrace instance")
        return self.instances[instance_name]

#    @property
#    def angr_mgr(self):
#        return self.__angr_mgr 

#    @angr_mgr.setter
#    def angr_mgr(self, angr_mgr):
#        self.__angr_mgr = angr_mgr

    def __init_kprobes(self):
        if self.instance_name is not None:
            return
        
        regex_pattern = re.compile(r"""
                ^(?P<probe_type>[pr])(?P<identifier>\d*):
                (?P<event_type>[^\/]+)\/
                (?P<event_name>[\S]+)\s+
                (?:(?P<module_name>[\w\-]+):)?
                (?P<target_function>[\w\-\._\[\]]+)
                (?:\s*\+\s*(?P<probe_offset>\d+))?
                (?:\s+(?P<extra>.+))?$
            """, re.VERBOSE)

        try:
            kprobes = self.kprobe_event_file_path.read_text()
        except Exception as e:
            raise Exception(f'error opening {self.kprobe_event_file_path}: {e}')

        for kprobe_line in kprobes.splitlines():
            m = regex_pattern.match(kprobe_line)
            if m is None:
                continue

            d = m.groupdict()
            kprobe = self.KprobeEvent(self,
                                        probe_type=d['probe_type'],
                                        identifier=int(d['identifier']) if d['identifier'] else None,
                                        event_type=d['event_type'],
                                        module_name=d['module_name'],
                                        event_name=d['event_name'],
                                        target_function=d['target_function'],
                                        probe_offset=int(d['probe_offset']) if d['probe_offset'] else 0,
                                        extra=d['extra'],
                                        prepopulated=True)

        self.kprobe_event_clear()
        self.kprobes_cleared = True


    def read_available_filter_functions(self):
        # Reading the available funcs is heavy and we might not need it, so do
        # it lazily
        if self.__available_funcs is not None:
            return
        self.__available_funcs = set()
        txt = self.trace_path.joinpath("available_filter_functions").read_text()
        self.__available_funcs = {l.strip() for l in txt.splitlines()}

    def __is_available_filter_function(self, sym:Symbol) -> bool:
        if '.' not in sym.name:
            return sym.name in self.available_funcs

        base_name = sym.name.split('.')[0]
        return (sym.name in self.available_funcs or
                base_name in self.available_funcs)

    @staticmethod
    def is_available_filter_function(sym:Symbol) -> bool:
        return Ftrace.main_instance().__is_available_filter_function(sym)

    def read_cached(self, prop:str) -> str:
        if prop not in self.cache:
            self.cache[prop] = self.trace_path.joinpath(prop).read_text().strip()
        return self.cache[prop]

    def write_cached(self, prop:str, content:str):
        self.trace_path.joinpath(prop).write_text(content)
        self.cache[prop] = content
    
    def __read_available_tracers(self):
        txt = self.trace_path.joinpath("available_tracers").read_text()
        self.available_tracers = txt.strip().split(' ')

    @property
    def buffer_total_size_kb(self) -> int:
        return int(self.read_cached("buffer_total_size_kb"))
    
    @buffer_total_size_kb.setter
    def buffer_total_size_kb(self, size:int):
        self.write_cached("buffer_total_size_kb", str(size))
    
    @property
    def buffer_size_kb(self) -> int:
        return int(self.read_cached("buffer_size_kb"))
    
    @buffer_size_kb.setter
    def buffer_size_kb(self, size:int):
        self.write_cached("buffer_size_kb", str(size))

    @property
    def func_filter(self) -> List[str]:
        return self.read_cached("set_ftrace_filter").split()

    @func_filter.setter
    def func_filter(self, funcs:Iterable[str]):
        self.write_cached("set_ftrace_filter", '\n'.join(funcs))

    def __read_kernel_table(self, start_sym:str, end_sym:str) -> Tuple[bytes, int, int]:
        start_table = self.sym_addrs[start_sym]
        stop_table = self.sym_addrs[end_sym]
        assert start_table is not None and stop_table is not None
        table = Kcore().read(start_table, stop_table - start_table)
        return table, start_table, stop_table

    def __read_jump_table(self):
        table, start_table, stop_table = self.__read_kernel_table('__start___jump_table', '__stop___jump_table') 

        for base in range(start_table, stop_table, 16):
            offset = base - start_table
            code_offset, _, _ = struct.unpack('iiL', table[offset:offset + 16])
            self.invalid_kprobe_addrs.append(base + code_offset)

    def __read_static_call_table(self):
        table, start_table, stop_table = self.__read_kernel_table('__start_static_call_sites', '__stop_static_call_sites')
            
        STATIC_CALL_SITE_INIT = 2
        for base in range(start_table, stop_table, 8):
            offset = base - start_table
            code_offset, key_offset = struct.unpack('ii', table[offset:offset + 8])
            addr = base + code_offset
            key = base + 4 + key_offset
            if not (key & STATIC_CALL_SITE_INIT):
                self.invalid_kprobe_addrs.append(addr)

    def read_invalid_kprobe_addrs(self):
        if self.invalid_kprobe_addrs is not None:
            return

        self.invalid_kprobe_addrs = list()
        self.__read_jump_table()
        self.__read_static_call_table()
        # The bug table is really dependent on the config, so ignore it

        # TODO: Read modules tables
        self.invalid_kprobe_addrs.sort()

    def is_invalid_kprobe_addr(self, addr) -> bool:
        assert self.invalid_kprobe_addrs is not None
        idx = bisect.bisect_left(self.invalid_kprobe_addrs, addr)
        return (idx >= 0 and idx < len(self.invalid_kprobe_addrs) and
                self.invalid_kprobe_addrs[idx] == addr)

    def is_kprobe_blacklisted(self, addr:int) -> bool:
        if self.kprobe_blacklist is None:
            with open('/sys/kernel/debug/kprobes/blacklist') as f:
                self.kprobe_blacklist = [
                    (int(m.group('start'), 16), int(m.group('end'), 16))
                    for line in f
                    if (m := self.blacklist_regex.match(line)) is not None
                ]
            list.sort(self.kprobe_blacklist, key=lambda x:x[0])

        if sys.version_info >= (3, 10):
            idx = bisect.bisect_right(self.kprobe_blacklist, addr, key=lambda e:e[0])
        else:
            for idx, e in enumerate(self.kprobe_blacklist):
                if e[0] > addr:
                    break

        for i in range(max(idx - 1, 0), min(idx + 1, len(self.kprobe_blacklist))):
            r = list.__getitem__(self.kprobe_blacklist, i)
            if r[0] <= addr and addr < r[1]:
                return True

        return False

    def is_valid_kprobe(self, addr: int) -> bool:
        b = Kcore().read(addr, 2)

        # Detect UD2: cannot set kprobes
        if b == b'\x0f\x0b':
            return False

        # We might want to use angr to get the instruction and also
        # prevent on indirect branches that anyhow are not allowed
        # by kprobes
        
        return ((not self.is_kprobe_blacklisted(addr)) and
                (not self.is_invalid_kprobe_addr(addr)))

    def kprobe_event_disable_all(self, force_quiet:bool=False):
        if self.kprobes_disabled:
            return 0
        #dirs = ([] if not event_probe_path.exists() else
        #        [d for d in event_probe_path.iterdir() if d.is_dir()])
#        for d in Pbar('disabling kprobes', dirs, unit="kprobe", disable=force_quiet):
#            d.joinpath('enable').write_text('0')

        for kprobe in Pbar('disabling kprobes', self.kprobes.values(), unit="kprobe", disable=force_quiet):
            kprobe.enable = False

        self.kprobes_disabled = True

    def kprobe_event_close(self, force_quiet:bool=False):
        if self.kprobe_event_file is None:
            return

        self.kprobe_event_disable_all(force_quiet)
        # IN ADDITION REMOVE THEM
        try:
            self.kprobe_event_file.close()
        except OSError as e:
            logging.warning("failed closing kprobe_event")

        self.kprobe_event_file = None

    @property
    def kprobe_event_file_path(self) -> pathlib.Path:
        return self.trace_path.joinpath("kprobe_events")

    def kprobe_event_open(self):
        if self.kprobe_event_file is not None:
            return

        try:
            self.kprobe_event_file = open(self.kprobe_event_file_path , 'w')
        except:
            raise Exception(f'error opening {self.kprobe_event_file_path}')

    def kprobe_event_reopen(self):
        self.kprobe_event_close()
        self.kprobe_event_open()

    def __kprobe_event_write(self, s:str) -> bool:
        file = self.kprobe_event_file

        if file is None:
            return False

        try:
            file.write(s)
            file.flush()
        except OSError as e:
            logging.info(f'error writing "{s}" to {file.name}: {e}')
            return False
        return True

    def kprobe_event_clear(self):
        if self.kprobes_cleared or not self.kprobe_event_file_path.exists():
            self.kprobes_cleared = True
            return

        self.kprobe_event_disable_all()
        self.kprobe_event_reopen()
        self.kprobes_cleared = True

        # Remove all the kprobes that we set
        for kprobe in self.kprobes.values():
            kprobe.removed = True
        self.kprobes = dict()

    def kprobe_event_write(self, s:str):
        logging.debug(f'writing "{s}" to {self.kprobe_event_file_path}')
        
        success = self.__kprobe_event_write(s + '\n')
        self.kprobes_cleared = False

        if not success:
            cached = '\n'.join(self.kprobe_cache) + '\n'
            self.kprobe_event_reopen()
            if not self.__kprobe_event_write(cached):
                logging.error('fatal error writing to kprobes')
            raise ValueError(f'error writing "{s}" to {self.kprobe_event_file_path}')

        self.kprobe_cache.append(s)

    @property
    def current_tracer(self) -> str:
        return self.read_cached('current_tracer')

    @current_tracer.setter
    def current_tracer(self, tracer:str):
        if tracer not in self.available_tracers:
            raise Exception(f'invalid tracer {tracer}')
        self.write_cached('current_tracer', tracer)

    def __get_pid(self, prop:str) -> List[int]:
        data = self.read_cached(prop)
        return [int(v.strip()) for v in data.splitlines()]
    
    def __set_pid(self, prop:str, pids:Union[int, List[int], None]):
        if pids is None:
            s = ''
        elif isinstance(pids, int):
            s = str(pids)
        else:
            s = '\n'.join([str(pid) for pid in pids])
        self.write_cached(prop, s)

    @property
    def pid(self) -> List[int]:
        return self.__get_pid("set_ftrace_pid")

    @pid.setter
    def pid(self, pids:List[int]):
        return self.__set_pid("set_ftrace_pid", pids)
    
    @property
    def event_pid(self) -> List[int]:
        return self.__get_pid("set_event_pid")

    @event_pid.setter
    def event_pid(self, pids:List[int]):
        return self.__set_pid("set_event_pid", pids)

    @property
    def event_notrace_pid(self) -> List[int]:
        return self.__get_pid("set_event_notrace_pid")

    @event_notrace_pid.setter
    def event_notrace_pid(self, pids):
        return self.__set_pid("set_event_notrace_pid", pids)

    @property
    def trace_clock(self) -> str:
        return self.read_cached('trace_clock')
    
    @trace_clock.setter
    def trace_clock(self, clock:str):
        self.write_cached('trace_clock', clock)

    @property
    def snapshot_file(self) -> pathlib.Path:
        return self.trace_path.joinpath('snapshot')

    def disable_snapshot(self):
        self.snapshot_file.write_text('0')

    def clear_snapshot(self):
        self.snapshot_file.write_text('1')
        self.snapshot_file.write_text('2')

    def get_bool(self, path:str) -> bool:
        return self.trace_path.joinpath(path).read_text()[0] != 0

    def set_bool(self, path:str, enable:bool):
        self.trace_path.joinpath(path).write_text(str(int(enable)))

    @property
    def irq_info(self) -> bool:
        return self.trace_path.joinpath('options/irq-info').read_text()[0] != 0
        
    @irq_info.setter
    def irq_info(self, enable:bool):
        self.set_bool('options/irq-info', enable)       

    def open_trace_pipe(self, is_async:bool=False) -> io.BufferedReader:
        k = 'async' if is_async else 'sync'
        if k in self.pipes:
            return self.pipes[k]

        self.pipes[k] = self.trace_path.joinpath("trace_pipe").open("r")
        if is_async:
            fctnl_flags = fcntl.fcntl(self.pipes[k].fileno(), fcntl.F_GETFL)
            fcntl.fcntl(self.pipes[k], fcntl.F_SETFL, fctnl_flags|os.O_NONBLOCK)
        return self.pipes[k]

    @property
    def trace_pipe(self) -> io.BufferedReader:
        return self.open_trace_pipe(False)
    
    @property
    def async_trace_pipe(self):
        return self.open_trace_pipe(True)

    def get_snapshot(self, skip_trace_events:List[str], resume_trace_events:List[str]) -> List[Dict[str, Any]]:
        """Get a snapshot of the current trace buffer."""
        entries = list()
        # For the callstack we need the last "func" entry. We cannot rely on it
        # being the last one, since kprobes can somehow get interleaved entries.
        last_func_entry = None

        # Find the symbols to track
        lines = self.snapshot_file.read_text().splitlines()
        skip_trace_strs = [s.split('/')[-1] for s in skip_trace_events]
        resume_trace_strs = [s.split('/')[-1] for s in resume_trace_events]

        found_exit, found_entry = False, False
        for l in Pbar("parse snapshot", items=lines):
            if l.startswith('#'):
                continue

            m = self.callstack_regex.match(l)
            if m is not None:
                if last_func_entry is None:
                    continue

                sd = m.groupdict()

                # kretprobe'd functions cannot be resolved; we will handle these
                # situations later
                callstack_addr = None if sd['sym'] == "[unknown/kretprobe'd]" else int(sd['addr'], 16)
                if last_func_entry['callstack'] is None:
                    last_func_entry['callstack'] = list()
                last_func_entry['callstack'].append(callstack_addr)
                continue

            m = self.ftrace_regex_payload.match(l)
            if m is None:
                continue
            
            d:Dict[str,Optional[Union[str,int,float,List]]] = m.groupdict()
            assert isinstance(d['payload'], str)
            payload = d['payload']
            del d['payload']

            if payload.startswith('Unknown type'):
                continue

            if payload == '<stack trace>':
                continue

            regex_list = [
                (self.ftrace_ret_regex, "ret"),
                (self.ftrace_func_regex, "func"),
                (self.ftrace_probe_regex, "probe"),
                (self.ftrace_syscall_enter_regex, "sysenter"),
                (self.ftrace_raw_syscall_exit_regex, "sysexit"),
                (self.ftrace_syscall_exit_regex, "sysexit"),
            ]

            for r in regex_list:
                m = r[0].match(payload)
                if m is None:
                    continue
                d.update(m.groupdict())
                d['type'] = r[1]
                break

            # Parse the hex values
            if 'vals' in d:
                assert isinstance(d['vals'], str)
                kvs = d['vals'].split(' ')
                hex_vals = {k: int(v, 16) for kv in kvs for k, v in (kv.split('='),)}
                d.update(hex_vals)
                del d['vals']

            if 'type' not in d:
                semi_idx = payload.find(':')
                if semi_idx != -1:
                    event_name = payload[0:semi_idx]
                    if event_name in skip_trace_strs:
                        d['type'] = 'irqenter'
                    elif event_name in resume_trace_strs:
                        d['type'] = 'irqexit'
                continue

            if not found_entry and d['type'] != 'sysenter':
                continue

            if d['type'] == 'sysexit':
                found_exit = True
                break

            found_entry = True

            for fld in d:
                if not isinstance(d[fld], str):
                    continue

                # Calm down mypy
                s:str = str(d[fld]).strip()

                # Convert to the right type
                if fld in {'offset', 'size', 'addr', 'to_ip', 'from_ip'} or s.startswith('0x'):
                    d[fld] = int(s, 16)
                elif fld in {'pid', 'cpu', 'err'}:
                    d[fld] = int(s)
                elif fld in {'time'}:
                    d[fld] = float(s)
                else:
                    d[fld] = s

            if d['type'] == 'func':
                d['callstack'] = None
                last_func_entry = d

            entries.append(d)

        if not found_entry or not found_exit:
            raise ValueError("failed to capture full snapshot")

        return entries

    @property
    def tracing_on(self) -> bool:
        return self.get_bool('tracing_on')

    @tracing_on.setter
    def tracing_on(self, enable:bool):
        self.set_bool('tracing_on', enable)

    @property
    def sym_addr(self) -> bool:
        return self.get_bool('options/sym-addr')

    @sym_addr.setter
    def sym_addr(self, enable:bool):
        self.set_bool('options/sym-addr', enable)

    @property
    def func_stack_trace(self) -> bool:
        return self.get_bool('options/func_stack_trace')
    
    @func_stack_trace.setter
    def func_stack_trace(self, enable:bool):
        self.set_bool('options/func_stack_trace', enable)

    @property
    def stacktrace(self) -> bool:
        return self.get_bool('options/stacktrace')
    
    @stacktrace.setter
    def stacktrace(self, enable:bool):
        self.set_bool('options/stacktrace', enable)

    @property
    def function_fork(self) -> bool:
        return self.get_bool('options/function-fork')

    @function_fork.setter
    def function_fork(self, enable:bool):
        self.set_bool('options/function-fork', enable)

    @property
    def event_fork(self) -> bool:
        return self.get_bool('options/event-fork')

    @event_fork.setter
    def event_fork(self, enable:bool):
        self.set_bool('options/event-fork', enable)

    def remove_all_probes(self):
        self.kprobe_event_clear()

    @property
    def available_funcs(self) -> Set[str]:
        self.read_available_filter_functions()
        assert self.__available_funcs is not None
        return self.__available_funcs
    
    def get_event(self, name: str):
        if name not in self.events:
            self.events[name] = self.Event(name, self)
        return self.events[name]
        
    class Event:
        path: pathlib.Path
        cache: Dict[str, str]

        def __init__(self, path, ftrace):
            self.ftrace = ftrace
            self.path = ftrace.trace_path.joinpath('events/' + path)
            self.cache = dict()

        def __get(self, filename:str, default:Optional[str]=None) -> Optional[str]:
            if not self.path.exists():
                if filename in self.cache:
                    del self.cache[filename]
                return default
            if filename not in self.cache:
                self.cache[filename] = self.path.joinpath(filename).read_text()
            return self.cache[filename]
        
        def __read(self, filename:str) -> str:
            v = self.__get(filename)
            assert v is not None
            return v
        
        def __write(self, filename:str, v: str, default:Optional[str] = None):
            if not self.path.exists():
                if v != default:
                    raise IOError('path does not exist')
                return
            self.path.joinpath(filename).write_text(v) 
            self.cache[filename] = v     

        @property
        def enable(self) -> bool:
            return self.__get('enable', default='0') != '0'
        
        @enable.setter
        def enable(self, v:bool):
            self.__write('enable', str(int(v)), default='0')

        @property
        def trigger(self) -> str:
            v = self.__read('trigger')
            return '' if v[0] == '#' else v

        @trigger.setter
        def trigger(self, v:str):
            v = v or ''

            old_trigger = self.trigger
            if old_trigger == v:
                return
            
            if old_trigger != '':
                old_trigger_key = old_trigger.split(' ')[0].split(':')[0]
                self.__write('trigger', '!' + old_trigger_key)

            if v != '':
                self.__write('trigger', v)

        @property
        def filter(self) -> str:
            return self.__read('filter').strip()
        
        @filter.setter
        def filter(self, v):
            self.__write('filter', v)

    class KprobeEvent(Event):
        removed: bool = False

        def __init__(self,
                     ftrace: 'Ftrace',
                     probe_type: str,
                     event_name: str,
                     module_name: str,
                     target_function: Union[Symbol, str],
                     probe_offset: int,
                     extra: str = '',
                     event_type: str = 'kprobes',
                     identifier: Optional[int] = None,
                     prepopulated: bool = False):
            self.probe_type = probe_type
            self.identifier = identifier
            self.event_type = event_type
            self.event_name = event_name
            self.module_name = module_name
            self.__target_function = target_function
            self.probe_offset = probe_offset
            self.extra = extra
            self.ftrace = ftrace

            event_path = f'{event_type}/{event_name}'

            # Check if the event is already registered
            if not prepopulated and ftrace.trace_path.joinpath(event_path).exists():
                raise IOError(f'Event {event_path} already exists')

            super(ftrace.KprobeEvent, self).__init__(event_path, ftrace)
            if not prepopulated:
                ftrace.kprobe_event_write(self.ftrace_str)
            
            ftrace.kprobes[self.event_path] = self

        def __str__(self):
            return hex(self.addr)

        def __repr__(self):
            module_name = self.module_name if self.module_name != '' else 'kernel'
            target_function = self.target_function if isinstance(self.target_function, str) else self.target_function.name

            return (f'''KprobeEvent("{self.probe_type}:
                        {self.event_type}:
                        {self.event_name}:
                        {module_name}:
                        {target_function}:
                        {hex(self.probe_offset)}:
                        {self.extra}")''')

        def __addr(self) -> int:
            assert isinstance(self.target_function, Symbol)
            return self.target_function.rebased_addr + self.probe_offset

        def __hash__(self) -> int:
            # For objects that we populated from the kprobe_events, hash everything. For objects
            # that we created ourselves, calculate the actual address.
            if isinstance(self.target_function, Symbol):
                return hash((self.__addr(), self.ftrace, self.extra, self.probe_type))
            else:
                return hash((self.probe_type, self.identifier, self.event_type, self.event_name,
                             self.__target_function, self.probe_offset, self.extra))
        
        @property
        def addr(self) -> int:
            if not isinstance(self.__target_function, Symbol):
                raise ValueError('target_function must be a Symbol')
            return self.__target_function.rebased_addr + self.probe_offset

        @property
        def ret(self) -> bool:
            return self.event_type == 'r'

        @property
        def enable(self) -> bool:
            if self.removed:
                return False
            return super().enable
        
        @enable.setter
        def enable(self, v:bool):
            assert(not self.removed)
            if v:
                self.ftrace.kprobes_disabled = False
            super(Ftrace.KprobeEvent, self.__class__).enable.fset(self, v) # type: ignore

        @property
        def target_function(self) -> str:
            f = self.__target_function
            return f.name if isinstance(f, Symbol) else f

        @property
        def ftrace_str(self) -> str:
            # TODO: add the module
            return f'{self.probe_type}:{self.event_path} {self.target_function}+{self.probe_offset} {self.extra}'
        
        @property
        def event_path(self) -> str:
            return f'{self.event_type}/{self.event_name}'