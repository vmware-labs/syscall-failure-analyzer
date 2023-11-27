# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Optional, Set, List, Dict, Tuple, Any, Union, List
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import defaultdict

import syscall
import itertools
from angrmgr import Angr
from arch import arch
from cle.backends import Symbol
from ftrace import Ftrace
from prmsg import pr_msg, Pbar
from reporter import Reporter
from syscall import SyscallInfo, ErrorcodeInfo

class IntelPTReporter(Reporter):
    branch_regex = re.compile(
            Ftrace.common_trace_pattern +
            r'(?P<id>\d+)\s+' +
            r'(?P<event>[^\:]+):(?P<ctx>[ku]):\s+' +
            r'(?P<from_ip>[0-9a-f]+)\s+' + 
            r'(?P<from_sym>[^\+]+)' +
            r'(\+0x(?P<from_off>[0-9a-f]+))? ' +
            r'\(' +
            r'(\[(?P<from_obj>[^\]]+)\])?' +
            r'(?P<from_sec>[^\)]*)' +
            r'\)' +
            r' =>\s+' +
            r'(?P<to_ip>[0-9a-f]+)\s+' +
            r'(?P<to_sym>[^\+]+)' +
            r'(\+0x(?P<to_off>[0-9a-f]+))? ' +
            r'\(' +
            r'(\[(?P<to_obj>[^\]]+)\])?' +
            r'(?P<to_sec>[^\)]*)' +
            r'\)')

    @staticmethod
    def parse_entries_batch(strings, start_line):
        results = []
        bpf_perf_event_output_indices = []
        exit_event_indices = []
        for i, string in enumerate(strings):
            match = IntelPTReporter.branch_regex.match(string)
            if match:
                d = match.groupdict()

                # Ignore PID -1 events. For some reason perf might emit them, but we
                # cannot associate them with a process, which makes their processing
                # non-trivial.
                if d['pid'] == '-1':
                    results.append(None)
                    continue

                d['time'] = float(d['time'])
                for field in ['to_sym', 'from_sym']:
                    if d[field] == '[unknown]':
                        d[field] = None
                for field in ['to_obj', 'from_obj']:
                    if d[field] == 'unknown':
                        d[field] = None
                for field in ['to_ip', 'from_ip', 'from_off', 'to_off']:
                    d[field] = d[field] and int(d[field], 16)
                for field in ['pid', 'id', 'cpu']:
                    d[field] = int(d[field])
                results.append(d)
                
                # Check the conditions for bpf_perf_event_output branches
                if ((d['from_sym'] or '').startswith('bpf_prog_') and
                    d.get('to_sym') == 'bpf_perf_event_output_tp'):
                    bpf_perf_event_output_indices.append(start_line + i)
                continue
            
            match = Ftrace.err_exit_regex.match(string)
            if False and match:
                d = match.groupdict()
                d['time'] = float(d['time'])
                d['pid'] = int(d['pid'])
                d['errcode'] = int(d['err'], 16) if d['err'] else int(d['err2'], 16)
                d['syscall_exit_nr'] = (int(d['syscall_exit_nr']) if d['syscall_exit_nr']
                                        else SyscallInfo.get_syscall_nr(d['syscall_exit_name']))
                for k in ['err', 'err2']:
                    del d[k]
                results.append(d)
                exit_event_indices.append(start_line + i)
                continue

            match = Ftrace.entry_exit_regex.match(string)
            if match:
                d = match.groupdict()
                syscall_entry = (d['syscall_enter_name'] is not None or
                                 d['syscall_enter_nr'] is not None)
                r = {
                    'time': float(d['time']),
                    'pid': int(d['pid']),
                    'proc': d['proc'],
                    'cpu': int(d['cpu']),
                    'type': 'syscall' if syscall_entry else 'syscall_exit',
                }
                if syscall_entry:
                    if d['syscall_args1'] is not None:
                        matches = re.findall(r'(\w+):\s*(0x[\da-fA-F]+)', d['syscall_args1'])
                        args = {k: int(v, 16) for k, v in matches}
                    else:
                        argument_values = d['syscall_args2'].split(', ')
                        args = {f'arg{i+1}': int(x, 16) for i, x in enumerate(argument_values)}

                    r.update({
                        'syscall_nr': (int(d['syscall_enter_nr']) if d['syscall_enter_nr']
                                        else SyscallInfo.get_syscall_nr(d['syscall_enter_name'])),
                        'syscall_args': args
                    })
                else:
                    r.update({
                        'errcode': int(d['err'], 16) if d['err'] else int(d['err2'], 16),
                        'syscall_nr': (int(d['syscall_exit_nr']) if d['syscall_exit_nr']
                                        else SyscallInfo.get_syscall_nr(d['syscall_exit_name']))
                    })
                results.append(r)
                continue

            results.append(None)
        return results, bpf_perf_event_output_indices, exit_event_indices

    @staticmethod    
    def entries_chunk_list(input_list, chunk_size):
        return [input_list[i:i + chunk_size] for i in range(0, len(input_list), chunk_size)]

    @staticmethod
    def parse_entries_batch_wrapper(args):
        return IntelPTReporter.parse_entries_batch(*args)

    def parse_trace(self, trace: List[str], errcode:Optional[int]=None) -> Tuple[List[Dict[str, Union[int, str, float]]], List[Dict]]:
        batch_size = 1000  # Set this to an appropriate value based on your dataset and hardware capabilities

        input_batches = self.entries_chunk_list(trace, batch_size)
        input_batches_with_start_line = [(batch, i * batch_size) for i, batch in enumerate(input_batches)]

        with ProcessPoolExecutor(max_workers=10) as executor:
            with Pbar(message="process trace", items=input_batches_with_start_line) as pbar:
                batch_results = list(executor.map(self.parse_entries_batch_wrapper, pbar))

        # Flatten the list of results and bpf_perf_event_output_indices
        results = [result for batch in batch_results for result in batch[0]]
        bpf_perf_event_output_indices = [index for batch in batch_results for index in batch[1]]
        exit_event_indices = [index for batch in batch_results for index in batch[2]]

        failures = []
        for index in bpf_perf_event_output_indices:
            pid = results[index]['pid']
            match = None
            for exit_index in exit_event_indices:
                if exit_index > index and results[exit_index].get('pid') == pid:
                    match = exit_index
                    break

            failure = {'index': index, 'pid': pid}
            if match is None:
                # TODO: reenable
                if False and errcode is None:
                    pr_msg('found a failure, but no data on the error code', level='ERROR')
                    continue
                failure['errcode'] = errcode
            else:
                failure['errcode'] = results[match]['errcode']
                failure['syscall'] = results[match]['syscall_exit_nr']
            failures.append(failure)

        return results, failures

    def is_intr_entry(self, entry:Dict[str, Any]) -> bool:
        return (entry.get('to_off') == 0 and
                entry.get('from_sym') != entry['to_sym'] and
                self.angr_mgr.is_interrupt_handler_addr(entry['to_ip']))
    
    def is_intr_exit(self, entry:Dict[str, Any]) -> bool:
        if entry.get('from_sym') not in arch.irq_exit_sym_names:
            return False
        insn = self.angr_mgr.get_insn(entry['from_ip'])
        return insn and arch.is_iret_insn(insn)

    def is_syscall_entry(self, entry:Dict[str, Any]) -> bool:
        # TODO: move to arch-specific code
        return entry.get('to_sym') in {'__entry_text_start', 'entry_SYSCALL_64', 'syscall_enter_from_user_mode'}

    def is_syscall_exit(self, entry:Dict[str, Any]) -> bool:
        return (entry.get('to_sym') == 'syscall_exit_to_user_mode' and
                entry['to_off'] == 0)

    def report(self) -> bool:
        n_reported = 0
        n_traces = len(self.traces)
        n_failures = len(self.failures)

        # TODO: coorelate the trace with the failure
        for failure in self.failures:
            for i_trace, trace in enumerate(self.traces):
                # Although we have a timestamp on the failure that we collected using eBPF,
                # it is using a different time source than perf, so we have no reasonable way
                # to correlate the two. Instead, we just look for the error code in the trace
                # and then look for the syscall entry/exit points around it.
                pr_msg(f"processing trace {i_trace+1}/{n_traces}", level='INFO')
                
                if not isinstance(trace, str):
                    raise SystemError('Intel-PT trace is not a string')

                trace_entries = trace.splitlines()

                parsed, trace_failures = self.parse_trace(trace_entries)

                #failures = self.get_errors(trace_entries)

                if len(trace_failures) == 0:
                    pr_msg('found no failures in trace', level='INFO')
                    continue

                for trace_failure in trace_failures:
                    failure_entries = parsed[:trace_failure['index']]
                    failure_errcode = failure['err']
                    failure_syscall = failure['syscall_nr']

                    failure_entries = [e for e in failure_entries if e is not None and e['pid'] == failure['pid']]

                    # Remove any entries in which the from_sym or to_sym is None
                    failure_entries = [e for e in failure_entries
                                    if e.get('from_sym', '') is not None and e.get('to_sym', '') is not None]

                    # TODO: Fix the filters based on the failure entries
                    if ((self.syscall_filter and self.syscall_filter != failure_syscall) or
                        (self.errcode_filter and self.errcode_filter != failure_errcode)):
                        continue

                    branches = self.skip_intr_entries(failure_entries)

                    # TODO: extract all syscalls, not just the last one
                    extracted = self.extract_last_syscall(branches)
                    if extracted is None:
                        continue

                    branches = extracted
                    branches = self.skip_fentry_entries(branches)

                    super().report_one(
                        branches = branches,
                        errcode = -failure_errcode,
                        simulate_all = True
                    )
                    n_reported += 1

                    if n_reported == n_failures:
                        return True

        return True

    def find_time(self, trace:List[str], time:float, before:bool) -> Optional[int]:
        """Find the index of the first entry with the given time"""
        # Bisect to find the time, but gracefully handle entries with no time
        s = 0
        e = len(trace)
        found = None
        while s < e:
            mid = (s + e) // 2
            # Only consider branch entries since their time is in sync with
            # the time we look for. If we do not have such entry, go forward
            # and then backward until we find one.
            for i in itertools.chain(range(mid, len(trace)), range(mid, -1, -1)):
                m = self.branch_regex.match(trace[i])
                if m is not None:
                    break
            if m is None:
                return None
            d = m.groupdict()
            e_time = float(d['time'])
            if e_time < time:
                if before:
                    found = max(mid, found or mid)
                s = mid + 1
            elif e_time == time:
                if before:
                    e = mid - 1
                    found = min(mid - 1, found or mid - 1)
                else:
                    s = mid + 1
                    found = max(mid + 1, found or mid + 1)
            else: # e_time > time
                if not before:
                    found = min(mid, found or mid)
                e = mid

#        assert found is not None
#        for i in range(found, 0, -1):
#            if Ftrace.err_exit_regex.match(trace[i]) is not None:
#                return i
        
        return found

    @staticmethod
    def search_in_chunk(args):
        chunk, regex_pattern, start_line = args
        matches = []

        for i, line in enumerate(chunk, start_line):
            match = regex_pattern.match(line)
            if match:
                matches.append(i)

        return matches

    @staticmethod
    def chunk_lines(lines, chunk_size):
        return [(lines[i:i + chunk_size], i) for i in range(0, len(lines), chunk_size)]

    @staticmethod
    def search_regex_multiprocess(lines: List[str], compiled_regex, max_workers=10, chunk_size=100):
        all_matches = []

        chunks = IntelPTReporter.chunk_lines(lines, chunk_size)

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(IntelPTReporter.search_in_chunk, (chunk, compiled_regex, start_line)) for chunk, start_line in chunks]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_matches.extend(result)

        return all_matches
    
    def skip_fentry_entries(self, trace:List[Dict]) -> List[Dict]:
        """Skip all fentry entries in the trace"""
        result:List[Dict] = []

        def is_untracked_sym(sym:str) -> bool:
            return sym in {'__fentry__', 'zen_untrain_ret', '__x86_return_thunk'} or sym.startswith('__x86_indirect_thunk')
        
        in_untracked = False
        in_fentry = False
        for entry in trace:
            from_sym = entry.get('from_sym', '')
            to_sym = entry.get('to_sym', '')
            from_ip = entry.get('from_ip', 0)
            to_ip = entry.get('to_ip', 0)
            is_untracked_target = is_untracked_sym(to_sym)

            # Skip all fentry until return.
            # TODO: consider handling nested
            if not in_untracked:
                if in_fentry:
                    try:
                        insn = self.angr_mgr.get_insn(from_ip)
                    except:
                        continue
                    if from_sym == '__fentry__' and arch.is_ret_insn(insn):
                        in_fentry = False
                    continue
                elif to_sym == '__fentry__':
                    in_fentry = True
                    continue
            
            is_untracked_target = (to_sym in {'__fentry__', 'zen_untrain_ret', '__x86_return_thunk'} or
                                    to_sym.startswith('__x86_indirect_thunk'))
 
            if in_untracked:
                if not is_untracked_target:
                    if len(result) > 0:
                        for k in ['to_sym', 'to_off', 'to_sec', 'to_ip']:
                            result[-1][k] = entry[k]
                    in_untracked = False
            else:
                # Add in both cases; we will fix the to_* fields later
                if is_untracked_target:
                    in_untracked = True
                    result.append(entry.copy())
                else:
                    result.append(entry)

        return result

    def skip_intr_entries(self, trace:List[Dict]) -> List[Dict]:
        result:List[Dict] = []
        enumerated = [e for e in enumerate(trace)]
        irq_entries = [e[0] for e in enumerated if self.is_intr_entry(e[1])]
        irq_exits = [e[0] for e in enumerated if self.is_intr_exit(e[1])]
        in_irq = 0
        irq_entries_i = 0
        irq_exits_i = 0
        start_idx = 0
        # Indexes to trace that reflects the last non-nested IRQ/exception entries/exits
        trace_irq_entry_i = None
        trace_irq_exit_i = None

        while irq_entries_i < len(irq_entries) or irq_exits_i < len(irq_exits):
            if (irq_entries_i < len(irq_entries) and (irq_exits_i >= len(irq_exits) or
                irq_entries[irq_entries_i] < irq_exits[irq_exits_i])):
                # IRQ entry
                if in_irq == 0:
                    trace_irq_entry_i = irq_entries[irq_entries_i]
                    result.extend(trace[start_idx:trace_irq_entry_i])
                    start_idx = trace_irq_entry_i + 1
                in_irq += 1
                irq_entries_i += 1
            else:
                # IRQ exit
                if in_irq == 0:
                    # We are not in an IRQ, but something went wrong. We will just clean the result and
                    # hope for the best.
                    pr_msg(f'IRQ exit without entry: {trace[irq_exits[irq_exits_i]]}', level = 'DEBUG')
                    result = []
                elif in_irq > 0:
                    in_irq -= 1
                    if in_irq == 0:
                        trace_irq_exit_i = irq_exits[irq_exits_i]

                        # Special handling for exception tables. If the return address
                        # does not match the exception address, we are going to add the
                        # entry and exit entries to the trace.
                        if (trace_irq_entry_i is not None and
                            trace[trace_irq_entry_i].get('from_ip') != trace[trace_irq_exit_i].get('to_ip')):
                            for i in [trace_irq_entry_i, trace_irq_exit_i]:
                                e = trace[i].copy()
                                e['exception'] = True
                                result.append(e)

                        start_idx = trace_irq_exit_i + 1
                         
                irq_exits_i += 1

        if not in_irq:
            result.extend(trace[start_idx:])

        return result

    def extract_last_syscall(self, trace:List[Dict]) -> Optional[List[Dict]]:
        enumerated = [e for e in enumerate(trace)]
        exit_entry_idxs = [i for i, e in enumerated if self.is_syscall_exit(e)]

        # Find the entry before the last exit
        if len(exit_entry_idxs) == 0:
            return None
        
        #exit_entry_idx = exit_entry_idxs[-1]
        exit_entry_idx = len(trace) - 1
        entries = enumerated[:exit_entry_idx+1]
      
        enter_entry_idxs = [i for i, e in enumerated if self.is_syscall_entry(e)]
        if len(enter_entry_idxs) == 0:
            return None
        enter_entry_idx = enter_entry_idxs[-1]
       
        # We still need to get rid of all unemulated code at the beginning of the trace.
        # As a hueristic, which might only fit x86-64, we will look for a call from
        # the entry point.
        for i in range(enter_entry_idx, exit_entry_idx):
            insn = self.angr_mgr.get_insn(entries[i][1]['from_ip'])
            if insn is None or not arch.is_call_insn(insn):
                continue
            if entries[i][1]['from_sym'] not in arch.syscall_entry_points:
                continue
            break
        
        enter_entry_idx = i
        if enter_entry_idx == exit_entry_idx:
            return None
        
        # Cut the end of the trace to the return address of the first call.
        # This is a heuristic that might not work for all architectures.
        expected_ret_addr = self.angr_mgr.next_insn_addr(insn)
        for i in range(exit_entry_idx, enter_entry_idx, -1):
            if entries[i][1]['to_ip'] == expected_ret_addr:
                break

        exit_entry_idx = i
        if enter_entry_idx == exit_entry_idx:
            return None

        return trace[enter_entry_idx:exit_entry_idx+1]

    def get_errors(self, trace:List[str]) -> List[Dict]:
        # The failures that were recorded had the wrong time source, so we need
        # to find the time of the failure in the trace. However, the location of
        # the failure in the trace, as indicated by the syscall entry/exit point
        # if not in sync with the branch trace. So we find the time of the
        # failure and would later find the branches in between. 
        err_list = []
        unmatched_exits = 0
        matched_syscalls = []
        enter_pid_dict = {}

        pr_msg("finding failures in trace...", level = "INFO")

        line_nums = self.search_regex_multiprocess(trace, Ftrace.complete_exit_regex)

        parsed = [(n, self.parse_trace_entry(trace[n])) for n in line_nums]

        for line_num, syscall_info in parsed:
            assert syscall_info is not None

            syscall_type = syscall_info["type"]
            pid = syscall_info["pid"]

            if syscall_type == "syscall_enter":
                enter_pid_dict[pid] = syscall_info

            elif syscall_type == "syscall_exit":
                if pid in enter_pid_dict:
                    matched_syscalls.append((enter_pid_dict[pid], syscall_info))
                    del enter_pid_dict[pid]
                else:
                    #matched_syscalls.append((None, line_num))
                    unmatched_exits += 1

        if unmatched_exits > 0:
            pr_msg(f"encountered {unmatched_exits} with incomplete trace", level = "INFO")
        
        for (entry, exit) in matched_syscalls:
            errcode = syscall.ret_to_err(exit['syscall_ret'])
            if errcode is None:
                continue

            f = {'start_time': entry['time'],
                'end_time': exit['time'],
                'errcode': -errcode,
                'syscall_nr': exit['syscall'],
                'pid': exit['pid'],
                'args': entry['syscall_args']}
            err_list.append(f)

        return err_list

    # TODO: Combine with kprobes function of remove_untracked_from_snapshot()
    def remove_untracked_branches(self, branches: List[Dict]) -> List[Dict]:
        # Various kernel code (e.g., context switch) performs complicated call/ret
        # interactions. So, we track nesting level based on addresses and not call
        # and rets.
        tracked_branches = list()
        nesting_level = 0
        callee_address, callee_sym, ret_to_ip = None, None, None
        for b in Pbar("clean trace", branches):
            from_ip, to_ip = b['from_ip'], b['to_ip']
            to_sym = to_ip and self.angr_mgr.get_sym(to_ip)
            from_insn = self.angr_mgr.get_insn(from_ip)

            if nesting_level == 0:
                if not arch.is_call_insn(from_insn):
                    tracked_branches.append(b)
                    continue
                
                # TODO: Do we want to check if the entire symbol is hooked?
                if not to_sym or self.angr_mgr.is_ignored_sym(to_sym) or self.angr_mgr.proj.is_hooked(to_ip):
                    callee_address = to_ip
                    ret_to_ip = self.angr_mgr.next_insn_addr(from_ip)
                    nesting_level = 1
                    tracked_branches.append({'from_ip': from_ip, 'to_ip': None})
                    tracked_branches.append({'from_ip': None, 'to_ip': ret_to_ip})
                else:
                    tracked_branches.append(b)
            elif to_ip == ret_to_ip and (from_insn is None or arch.is_ret_insn(from_insn)):
                nesting_level -= 1
            elif ((not callee_address or from_ip == callee_address) 
                  and (from_insn is not None and arch.is_call_insn(from_insn))):
                nesting_level += 1

        return tracked_branches
    
    @property
    def detailed_trace(self) -> bool:
        return False