# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import logging
import abc
import io
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
import colors
import pathlib
import copy

from syscall import SyscallInfo, ErrorcodeInfo
from ftrace import Ftrace
from angrmgr import Angr
from angrsim import AngrSim
from arch import arch
from cle.backends import Symbol
from prmsg import pr_msg, uptime
from addr2line import Addr2Line

class Reporter(metaclass=abc.ABCMeta):
    def __init__(self,
                 objs: List[io.BufferedReader],
                 syscall_filter: Optional[int],
                 errcode_filter: Optional[int],
                 occurances_filter: Optional[Set[int]],
                 angr_mgr: Angr,
                 print_stats: bool,
                 failures: List[Dict[str, Any]],
                 traces: List[Union[List[Dict[str, Union[int, str, float]]], str]],
                 src_path: Optional[str] = None,
    ):
        self.objs = objs
        self.syscall_filter = syscall_filter
        self.errcode_filter = errcode_filter
        self.occurances_filter = occurances_filter
        self.failures = failures
        self.kallsyms = None
        self.angr_mgr = angr_mgr
        self.print_stats = print_stats
        self.traces = traces
        self.src_path = src_path and pathlib.Path(src_path)

    @abc.abstractmethod
    def report(self):
        pass

    @property
    @abc.abstractmethod
    def detailed_trace(self):
        pass

    def do_print_stats(self, errcode:int, sim_attempts:int, branches:List, sim_stats:Dict[str, Union[List, int]]):
        pr_msg("---", new_line_after = True, level='DATA')
        pr_msg(f"errorcode: {errcode} [{ErrorcodeInfo.get_name(errcode)}]", level='DATA')
        pr_msg(f"divergence: {sim_stats['simulation diverged']}", level='DATA')
        pr_msg(f"functions: {sim_attempts}", level='DATA')
        pr_msg(f"branches: {len(branches)}", level='DATA')
        pr_msg(f"failure returning symbol index: {sim_stats['failure returning symbol index']}", level='DATA')
        pr_msg(f"failure reutrning function index: {sim_stats['failure returning function index']}", level='DATA')
        pr_msg(f"callstack function depth: {sim_stats['callstack function depth']}", level='DATA')
        pr_msg(f"callstack: {sim_stats['depth']}", level='DATA')
        pr_msg(f"analysis time: {int(uptime())}", level='DATA')
        pr_msg(f"recording time: {sim_stats.get('simulation time', 'N/A')}", level='DATA')
        if 'backtrack' in sim_stats:
            pr_msg(f'candidates: {sim_stats["divergence points"]}', level='DATA')
            pr_msg(f'backtracking: {sim_stats["backtrack"]}', level='DATA')
        pr_msg('', level='DATA', new_line_after = True)

    def get_unsimulated_callstack(self, branches: List[Dict[str, Any]], end: int) -> List[int]:
        callstack = []
        first = True

        # Go from the end of the trace to the return point of the function we
        # care about, and build the callstack
        for branch in reversed(branches[end + 1:]):
            from_ip = branch['from_ip']
            to_ip = branch['to_ip']
            if from_ip is None:
                continue
            insn = from_ip and self.angr_mgr.get_insn(from_ip)

            if arch.is_ret_insn(insn) and to_ip is not None:
                if first:
                    callstack.append(to_ip)
                callstack.append(from_ip)
            elif arch.is_call_insn(insn) and len(callstack) > 0:
                callstack.pop()
            first = False

        callstack.reverse()
        return callstack

    def get_entry_callstack(self, branch: Dict[str, Any]) -> Optional[List[int]]:
        if 'callstack' not in branch:
            return None
        # Skip the caller and callee on top of the callstack.
        # TODO: for consistency it would be best to ensure the callstack is using
        # the call addresses instead of the return addresses, and then remove this
        # manipulation.
        prev_ips = [self.angr_mgr.prev_insn_addr(ip) for ip in branch['callstack'][2:]]
        return [ip for ip in prev_ips if ip is not None]

    def report_one_fallback(self,
                            branches: List[Dict[str, Union[int, Dict[str, int], None, List[int]]]],
                            errcode: int,
                            order: List[Tuple[int, int]],
        ) -> bool:
        '''Report a failure using the fallback method, which is to just print the
        callstack of the function that outermost function that returned the error'''
        start, end = order[-1]
        ret = branches[end - 1].get('ret', None)
        if not isinstance(ret, int) or not ErrorcodeInfo.is_error_code(ret, errcode):
            return False

        callstack = (self.get_entry_callstack(branches[start]) or
                     self.get_unsimulated_callstack(branches, end))

        assert isinstance(callstack, list)
        caller_address = branches[start]['from_ip']
        callee_address = branches[start]['to_ip']
        assert isinstance(caller_address, int)
        assert isinstance(callee_address, int)
        callstack = [callee_address, caller_address] + callstack
        res = {
            'callstack': callstack,
            'failure returning symbol index': 0
        }
        self.show_results(res)
        return True

    def report_one(self,
                   branches: List[Dict[str, Union[int, Dict[str, int], None, List[int]]]],
                   errcode: int,
                   sim_syms: Optional[Set[Symbol]] = None,
                   simulate_all: bool = False,
    ):
        if self.errcode_filter and errcode != self.errcode_filter:
            return

        if simulate_all:
            order = [(0, len(branches))]
        else:
            order = self.get_analysis_order(branches, errcode)

        # TODO: get rid off. Instead, get_sym() or something should make this cleanup
        if sim_syms is not None:
            self.angr_mgr.remove_unsupported_pyvex_insn(sim_syms)

        avoid_repeated_syms = True
        tried_syms = set()
        success = False
        sim_attempts = 0
        for start, end in order:
            sim_attempts += 1
            ip = branches[start]['to_ip']
            if ip is None:
                continue
            sym = self.angr_mgr.get_sym(ip)
            if sym is None:
                continue
            if avoid_repeated_syms and sym in tried_syms:
                continue
            if (self.angr_mgr.is_skipped_sym(ip) or
                self.angr_mgr.is_fastpath_to_ret(ip) or
                self.angr_mgr.is_fastpath_to_out(ip)):
                continue
            pr_msg(f"trying {sym.name}()...", level="INFO")
            tried_syms.add(sym)

            sim = AngrSim(
                angr_mgr = self.angr_mgr,
                branches = branches[start:end],
                errcode = errcode,
                has_calls = False,
                sim_syms = sim_syms,
                detailed_trace = self.detailed_trace
            )

            try:
                res = sim.simulate()
            except SystemError as e:
                pr_msg(f'retrying: {e}', level='WARN')
                continue

            if 'failure_stack' not in res:
                continue

            simulation_callstack = res['failure_stack']
            assert isinstance(simulation_callstack, list)
           
            unsimulated_callstack = (self.get_entry_callstack(branches[start]) or
                                    self.get_unsimulated_callstack(branches, end))

            assert isinstance(unsimulated_callstack, list)
            callstack = simulation_callstack + unsimulated_callstack

            errorcode_return_depth = res['errorcode return depth']
            assert isinstance(errorcode_return_depth, int)

            res['callstack'] = callstack
            res['failure returning symbol index'] = max(len(callstack) - len(unsimulated_callstack) - errorcode_return_depth - 1, 0)

            self.show_results(res)

            if self.print_stats:
                res['depth'] = len(callstack)
                self.do_print_stats(errcode, sim_attempts, branches, res)
            success = True
            break

        # The very least look at the most external function return value
        if not success:
            success = self.report_one_fallback(branches, errcode, order)

        if not success:
            pr_msg("analysis failed", level="ERROR")

    def change_to_relative_path(self, path: str) -> str:
        if len(path) == 0 or path[0] != '/':
            return path
        match = re.search(r'linux-\d+\.\d+\.\d+/(.*)', path)
        if match:
            return match.group(1)
        return path

    def get_callstack_locations(self, callstack: List[int]) -> List[Dict[str, Any]]:
        addr2line = Addr2Line.get_instance()

        addr_to_base = {a: self.angr_mgr.base_addr(a) for a in callstack}
        base_lines_dict = addr2line.run(addr_to_base.values())

        # change absolute paths to relative paths
        for locs in base_lines_dict.values():
            for loc in (locs or []):
                loc['file'] = self.change_to_relative_path(loc['file'])

        # map addresses to locations
        locs = {a: base_lines_dict[addr_to_base[a]] for a in callstack}

        callstack_locations: List[Dict] = []
        for addr in callstack:
            try:
                sym = self.angr_mgr.get_sym(addr)
            except ValueError:
                sym = None

            callstack_locations.append({
                'addr': addr,
                'sym': sym,
                'offset': sym and addr - sym.rebased_addr,
                'locs': locs.get(addr),
            })

        return callstack_locations

    def analyze_source_callstack(self, res:Dict):
        callstack = res['callstack']
        failure_returning_symbol_index = res['failure returning symbol index']
        callstack_locations = self.get_callstack_locations(callstack)
        failure_returning_function_index = 0
        callstack_function_depth = 1

        source_callstack:List[Dict] = []

        for i, callstack_location in enumerate(callstack_locations):
            locs = callstack_location['locs']

            n_funcs = max(len(locs), 1)
            if failure_returning_symbol_index is not None and failure_returning_symbol_index > i:
                failure_returning_function_index += n_funcs

            callstack_function_depth += n_funcs

            if locs is None:
                source_callstack.append(callstack_location)
                continue

            for loc in locs:
                entry = copy.copy(callstack_location)
                del entry['locs']
                entry.update({
                    'file': loc['file'],
                    'line': loc['line'],
                    'col': loc.get('col'),
                    'func': loc['func'],
                })
                source_callstack.append(entry)
    
        res.update({
            'failure returning function index': failure_returning_function_index,
            'callstack function depth': callstack_function_depth,
            'source callstack': source_callstack
        })

    def read_surrounding_code(self, res:Dict):
        source_callstack = res['source callstack']
        if len(source_callstack) == 0:
            return

        to_extract_indexes = {0}
        to_extract_indexes.add(res['failure returning function index'])

        for idx in to_extract_indexes:
            e = source_callstack[idx]
            if e.get('file') is None:
                continue
            try:
                code = self.extract_surrounding_code(line=e['line'],
                                                     col=e.get('col', 1),
                                                     file_name=e['file'])
                e['code'] = code
            except FileNotFoundError as e:
                pr_msg(str(e), level='WARN', new_line_before=True)

    def print_surrounding_code(self, res:Dict):
        index_message = [(0, 'root-cause')]

        if res['failure returning symbol index'] != 0:
            index_message.append((res['failure returning symbol index'], 'failure-returning'))

        for idx, msg in index_message:
            callstack_entry = res['source callstack'][idx]
            if callstack_entry.get('code'):
                pr_msg(f'code around {msg}, {callstack_entry["func"]}():', level='TITLE', new_line_before=True)
                pr_msg(callstack_entry['code'], level='DATA', new_line_after=True)
                break

    def show_results(self, res:Dict):
        self.analyze_source_callstack(res)
        self.read_surrounding_code(res)
        self.print_callstack(res)
        self.print_surrounding_code(res)

    def print_callstack(self, res:Dict):
        failure_returning_function_index = res['failure returning function index']
        pr_msg("callstack (decoding):", level="TITLE", new_line_before=True)

        for i, e in enumerate(res['source callstack']):
            addr = e['addr']
            sym = e['sym']
            bin_loc = hex(addr) if sym is None else f'{sym.name}+{e["offset"]}'

            if 'file' not in e:
                fileline = '?:?'
            else:
                col_str = f':{e["col"]}' if e['col'] is not None else '' 
                fileline = f'{e["file"]}:{e["line"]}{col_str}'

                failure_pointer = ' <--' if failure_returning_function_index == i else ''

                pr_msg("{0: <40}  {1: <40}  {2}() {3}".format(
                    bin_loc, fileline, e['func'], failure_pointer), level='DATA')

    def get_analysis_order(self,
                           branches: List[Dict],
                           errcode: Optional[int]) -> List[Tuple[int,int]]:
        tree:Dict[str, Union[List, int, bool]] = {'children': [], 'start': 0, 'end': len(branches), 'root': True}
        n:Dict[str, Any]
        cur = tree
        i = len(branches) - 1
        stack:List[Dict[str, Any]] = []

        # We are going to process the entries in reverse, since we know we have
        # the end of the trace, but the beginning might be missing.
        while i >= 0:
            b = branches[i]
            ip = b['from_ip']
            insn = ip and self.angr_mgr.get_insn(ip)
            if insn and arch.is_call_insn(insn) and len(stack) != 0:
                cur['start'] = i
                cur = stack.pop()
            elif not insn or arch.is_ret_insn(insn):
                # As we do not know where the call is, mark it as the beginning
                # of the trace, for cases where we have a ret without a call.
                n = {'children': [], 'start': 0, 'end': i + 1}

                assert isinstance(cur['children'], list)
                cur['children'].insert(0, n)

                stack.append(cur)
                cur = n

            i -= 1

        # Scan from the rightmost leaf and add to results
        stack = [tree]
        results = list()
        while True:
            n = stack[-1]
            if len(n['children']) != 0:
                stack.append(n['children'][-1])
                continue

            if 'root' in n:
                break

            parent = stack[-2]
            parent['children'].pop()
            results.append((n['start'], n['end']))
            stack.pop()
        
        results = [r for r in results
                    if (branches[r[1] - 1]['from_ip'] is not None and
                    (errcode is None or 'ret' not in branches[r[1] - 1] or
                    ErrorcodeInfo.is_error_code(branches[r[1] - 1]['ret'], errcode)))]

        return results
    
    def parse_trace_entry(self, line:str) -> Optional[Dict]:
        """
        Parse a single entry of the trace file.
        """
        m = Ftrace.entry_exit_regex.match(line)
        if m is None:
            return None
        
        raw = m.groupdict()
        d:Dict[str, Any] = dict()

        d['time'] = float(raw['time'])
        d['cpu'] = int(raw['cpu'])
        d['pid'] = int(raw['pid'])

        if raw['syscall_enter_name'] is not None:
            args = []
            for arg in raw['syscall_args'].split(','):
                k, v = arg.split(':')
                args.append((k, int(v, 16)))
            d['syscall_args'] = args
            d['type'] = 'syscall_enter'
            d['syscall'] = SyscallInfo.get_syscall_nr(raw['syscall_enter_name'])

        elif raw['syscall_exit_name'] is not None:
            d['type'] = 'syscall_exit'
            d['syscall'] = SyscallInfo.get_syscall_nr(raw['syscall_exit_name'])
            d['syscall_ret'] = int(raw['err2'], 16)
        
        elif raw['syscall_exit_nr'] is not None:
            d['type'] = 'syscall_exit'
            d['syscall'] = int(d['syscall_exit_nr'])
            d['syscall_ret'] = int(raw['err'], 16)
        
        return d

    def tokenize_c_code(code):
        # Regular expression pattern to match common C tokens
        pattern = r'\b[_a-zA-Z][_a-zA-Z0-9]*\b|[-+*/%=<>!&|^~]?=|[-+*/%<>!&|^~]|\d+\.\d+|\d+|".*?"|\'.*?\'|[(){}[\],.;]'
        return [(match.start(), match.group()) for match in re.finditer(pattern, code)]

    @staticmethod
    def get_tokens_around_column(code, column):
        tokens = Reporter.tokenize_c_code(code)
        before_token = ''
        current_token = ''
        after_token = ''

        for i, (start, token) in enumerate(tokens):
            if start <= column < start + len(token):
                current_token = token
                before_token = code[:start]
                after_token = code[start + len(token):]
                break

        return before_token, current_token, after_token

    def extract_surrounding_code(self, line:int, col:int, file_name:str) -> Optional[str]:
        if self.src_path is None:
            return None
        
        assert isinstance(self.src_path, pathlib.Path)
        file = self.src_path / file_name
        try:
            lines = file.read_text().splitlines()
        except FileNotFoundError:
            raise FileNotFoundError(f'Could not find file {file}')

        start_line = max(0, line - 20)
        end_line = start_line + 40
        code = lines[start_line:end_line]
        line_offset = line - start_line - 1
        if col == 0:
            code[line_offset] = colors.color(f'{code[line_offset]}     <<<' , fg='red')
        else:
            before_token, failure_token, after_token = self.get_tokens_around_column(code[line_offset], col - 1)
            code[line_offset] = (before_token + 
                                 colors.color(f'{failure_token}', fg='red') +
                                 after_token +
                                 colors.color(f'    <<<' , fg='red'))
        enumerated = enumerate(code, start_line)
        return '\n'.join(f'{i+1:4} {l}' for i, l in enumerated)