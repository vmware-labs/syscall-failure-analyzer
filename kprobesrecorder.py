# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import logging
from typing import Optional, Set, List, Dict, Tuple, Iterable, Any, Union
from collections import deque, defaultdict

import ptrace
from ptrace.debugger.process import PtraceProcess
from ptrace.syscall.ptrace_syscall import PtraceSyscall

from arch import arch
from cle.backends import Symbol
from capstone import CsInsn

from kcore import Kcore
from ftrace import Ftrace
from recorder import Recorder
from prmsg import pr_msg, Pbar, warn_once

class KProbesRecorder(Recorder):
    SKIP_TRACE_EVENTS: List[str] = [
           'irq/irq_handler_entry',
           'irq_vectors/call_function_entry',
           'irq_vectors/call_function_single_entry',
           'irq_vectors/error_apic_entry',
           'irq_vectors/local_timer_entry',
           'irq_vectors/reschedule_entry',
           'irq_vectors/spurious_apic_entry',
           'irq_vectors/thermal_apic_entry',
           'irq_vectors/threshold_apic_entry',
    ]

    RESUME_TRACE_EVENTS: List[str] = [
           'irq/irq_handler_exit',
           'irq_vectors/call_function_exit',
           'irq_vectors/call_function_single_exit',
           'irq_vectors/error_apic_exit',
           'irq_vectors/local_timer_exit',
           'irq_vectors/reschedule_exit',
           'irq_vectors/spurious_apic_exit',
           'irq_vectors/thermal_apic_exit',
           'irq_vectors/threshold_apic_exit',
    ]

    NORETURN_FUNCS = {
        '__stack_chk_fail',
        'fortify_panic',
    }

    def __init__(self, **kwargs):
        self.pending_signals = defaultdict(deque)
        self.kprobes = dict()

        kwargs.pop('tmp_path', None)
        kwargs['kcore'] = Kcore()
        super().__init__(**kwargs)
        self.ftrace = Ftrace.main_instance(self.angr_mgr)

    def set_probes(self, addrs:Iterable[int]) -> List[int]:
        probes = list()

        for addr in Pbar("setting probes", items=addrs, unit="kprobe"):
            if self.ftrace.is_kprobe_blacklisted(addr):
                raise ValueError(f'kprobe on {hex(addr)} is blacklisted')
            probe = self.get_kprobe(addr = addr, extra = arch.ftrace_state_str)
            if probe is None:
                logging.error(f'could not set probe on {hex(addr)}')
            else:
                probes.append(probe)

        probes.sort(key=lambda x: x.addr)
        for probe in probes:
            probe.enable = True

        return probes

    def get_kprobe(self,
                   addr: int,
                   ret: bool = False,
                   extra: str = ''):
        key = (addr, ret)
        assert key is not None

        if not self.ftrace.is_valid_kprobe(addr):
            return None

        prefix = 'r' if ret else 'p'
        ename = f'{prefix}_{hex(addr)}'

        # We always use _stext as the target function, since there might be multiple
        # symbols with the same name.
        assert self.angr_mgr is not None
        target_sym = self.angr_mgr.get_sym('_stext')
        offset = addr - target_sym.rebased_addr
        assert offset >= 0

        kprobe = self.ftrace.KprobeEvent(
                     ftrace = self.ftrace,
                     probe_type = prefix,
                     event_name = ename,
                     module_name = '',
                     target_function = target_sym,
                     probe_offset = offset,
                     extra = extra)

#        self.kprobes[key] = kprobe
        return kprobe

    def set_ret_probes(self, syms:Set[Symbol]) -> List:
        events = list()
        for sym in Pbar("setting ret probes", items=syms, unit="symbol"):
            e = self.get_kprobe(addr = sym.rebased_addr, ret=True, extra='ret=$retval')
            if e is not None:
                events.append(e)

        for e in events:
            e.enable = True
        return events

    def record(self, args:List[str]):
        """
        Record function to trace kernel failures using kprobes

        :param args: command line arguments
        """
        assert self.angr_mgr is not None

        ftrace = Ftrace.main_instance(self.angr_mgr)
        ftrace.tracing_on = False

        stext_addr = self.angr_mgr.get_sym_addr("_stext")
        assert stext_addr is not None
        ftrace.kprobe_event_disable_all()

        ftrace.init_kprobe_base("_stext", self.angr_mgr.get_sym_addr)
        pr_msg("starting the process...", level='TITLE', new_line_before=True)

        try:
            self.init_process(args)
        except (FileNotFoundError, PermissionError) as e:
            pr_msg(f"error starting process: {e}", level="FATAL")
            return 0

        ftrace.buffer_size_kb = self.snapshot_size
        ftrace.irq_info = False
        ftrace.event_fork = False
        ftrace.function_fork = False
        sys_exit_event = self.set_sysexit_filter(ftrace, True)
        ftrace.stacktrace = False
        ftrace.func_stack_trace = True

        trace_events = [
            ftrace.get_event(ev)
            for ev in ['raw_syscalls/sys_enter'] + self.SKIP_TRACE_EVENTS + self.RESUME_TRACE_EVENTS
        ] + [sys_exit_event] 
       
        while True:
            # Cleanup if we did not finish nicely the last error
            ftrace.remove_all_probes()
            ftrace.current_tracer = 'nop'
            ftrace.func_filter = []
            ftrace.sym_addr = True           
            for ev in trace_events:
                ev.enable = False

            pr_msg("waiting for failure...", level='TITLE', new_line_before=True)
            syscall = self.wait_for_syscall(None)
            if syscall is None:
                pr_msg("execution ended", level="INFO")
                break

            process = syscall.process
            ftrace.pid = process.pid
            ftrace.event_pid = process.pid

            self.print_syscall_info(syscall)

            pr_msg('stage 1: producing call graph', level='TITLE', new_line_before=True)
            ftrace.current_tracer = 'function'

            for ev in trace_events:
                ev.enable = True

            try:
                snapshot = self.rerun_get_snapshot(process, syscall)
            except Exception as e:
                pr_msg(f'error: {e}', level="ERROR")
                continue

            snapshot = self.cleanup_callstack(snapshot)
            snapshot = self.remove_snapshot_irqs(snapshot)
            trace_syms = self.get_ftrace_snapshot_syms(snapshot)

            ftrace.tracing_on = False

            pr_msg(f'stage 2: obtaining return values ({len(trace_syms)} functions)',
                   level='TITLE', new_line_before=True)

            ret_probes = self.set_ret_probes(trace_syms)
            trace_syms.intersection_update([self.angr_mgr.get_sym(probe.addr) for probe in ret_probes])

            if not self.set_func_tracing(trace_syms):
                exit(1)
            
            try: 
                snapshot = self.rerun_get_snapshot(process, syscall)
            except Exception as e:
                pr_msg(f'error: {e}', level="ERROR")
                continue
            
            ftrace.remove_all_probes()
            snapshot = self.cleanup_callstack(snapshot)
            snapshot = self.remove_snapshot_irqs(snapshot)
            snapshot = self.remove_untracked_from_snapshot(snapshot)
            trace_syms = self.get_ftrace_snapshot_syms(snapshot)

            pr_msg("stage 3: creating trace", level='TITLE', new_line_before=True)

            reachable_syms = self.angr_mgr.process_reachable_syms(trace_syms)
            probe_addrs, probe_syms = self.tracking_probe_addrs(reachable_syms)
            self.set_ret_probes(probe_syms)

            if not self.set_func_tracing(probe_syms):
                exit()
            self.set_probes(probe_addrs)
            snapshot = self.rerun_get_snapshot(process, syscall)
            ftrace.remove_all_probes()
           
            snapshot = self.cleanup_callstack(snapshot)
            snapshot = self.remove_snapshot_irqs(snapshot)
            # TODO: Save the reachable syms
            snapshot = self.remove_untracked_from_snapshot(snapshot, probe_syms)

            # Save regardless to live analysis
            self.log_kprobes_failure(syscall=syscall,
                                     trace=snapshot,
                                     pid=process.pid,
                                     probe_addrs=probe_addrs,
                                     sim_syms=reachable_syms)
            
            if self.early_stop:
                for p in self.dbg.list:
                    p.kill()
                break
                
        self.save_failures("kprobes")

        # turn everything off again
        for ev in trace_events:
            ev.enable = False

        ftrace.current_tracer = 'nop'
        ftrace.tracing_on = False
        ftrace.func_stack_trace = False
        ftrace.pid = []
        ftrace.event_pid = []
        sys_exit_event.trigger = None

    def get_ftrace_snapshot_syms(self, snapshot:List[Dict[str,Any]]) -> Set[Symbol]:
        assert self.angr_mgr is not None

        syms = {entry['callstack_syms'][0] for entry in snapshot
                      if entry['type'] == 'func' and 'callstack_syms' in entry}

        syms = {sym for sym in syms if sym and not self.is_invalid_func_probe(sym) and 
                                    not self.angr_mgr.is_noprobe_sym(sym)}

        # Ensure we can disasm each symbol
        syms = {sym for sym in syms if self.angr_mgr.disasm_sym(sym)}

        return syms
            

    def remove_untracked_from_snapshot(self, snapshot:List[Dict], syms:Optional[Set[Symbol]]=None) -> List[Dict]:
        assert self.angr_mgr is not None

        entry_syms = {self.angr_mgr.get_sym(s) for s in arch.syscall_entry_points}
        found_entry_point = False
        cleaned = list()
        untracked = 0
        ignored_caller_syms = {self.angr_mgr.get_sym(s) for s in arch.syscall_entry_points}
        
        for l in Pbar("cleaning ftrace", items=snapshot, unit="line"):
            to_sym = l['callstack_syms'][0] if len(l.get('callstack_syms', [])) > 0 else None
            from_sym = l['callstack_syms'][1] if len(l.get('callstack_syms', [])) > 1 else None

            if not found_entry_point:
                if l['type'] != 'func' or from_sym not in entry_syms:
                    continue
                found_entry_point = True

            if l['type'] == 'func':
                if untracked > 0:
                    untracked += 1
                    continue

                for callstack_sym in l['callstack_syms']:
                    if callstack_sym and callstack_sym.name in arch.syscall_entry_points:
                        break

                    if (callstack_sym is None or
                        self.angr_mgr.is_noprobe_sym(callstack_sym) or
                        (syms is not None and callstack_sym not in syms|entry_syms|ignored_caller_syms)):
                        untracked = 1
                        break

                if untracked > 0:
                    continue

                # Ignore interrupts, exceptions
                prev_insn = self.angr_mgr.get_prev_insn(l['from_ip'])
                if prev_insn is None or not arch.is_branch_insn(prev_insn):
                    pr_msg(f'failed insn {prev_insn} to {hex(l["to_ip"])}', level="ERROR")
                    assert(0 == 1)
                    continue

                if to_sym is None or (syms is not None and self.is_invalid_func_probe(to_sym)):
                    untracked = 1
                    continue
                
            elif l['type'] == 'ret':
                if untracked > 0:
                    untracked -= 1
                    continue

            if untracked == 0:
                cleaned.append(l)

        return cleaned

    def log_kprobes_failure(self,
                            syscall: PtraceSyscall,
                            trace: List[Dict[str, Union[int, str, float, List]]],
                            pid:int,
                            probe_addrs:Iterable[int],
                            sim_syms:Iterable[Symbol]):
        failure = {
            'syscall': syscall.syscall,
            'errcode': -syscall.result,
            'trace_id': len(self.traces),
            'pid': pid,
            'probe_addrs': probe_addrs,
            'sim_syms': [s.rebased_addr for s in sim_syms],
        }
        for trace_entry in trace:
            trace_entry.pop('callstack_syms', None)

            # TODO: delete some more useless stuff

        self.traces.append(trace) # type: ignore
        self.failures.append(failure)

    def rerun_get_snapshot(self, process:PtraceProcess, failing_syscall:PtraceSyscall) -> List[Dict[str, Any]]:
        ftrace = Ftrace.main_instance()
        ftrace.clear_snapshot()
        ftrace.tracing_on = True
        self.restart_syscall(process, failing_syscall)
        syscall = self.wait_for_syscall(process)
        ftrace.tracing_on = False

        if syscall is None or syscall.result != failing_syscall.result:
            raise ValueError("reproduction error")
        
        assert syscall.process == process
        assert syscall.instr_pointer == failing_syscall.instr_pointer

        s = ftrace.get_snapshot(self.SKIP_TRACE_EVENTS, self.RESUME_TRACE_EVENTS)
        return s
    
    def cleanup_callstack(self, trace:List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        addr_to_sym:Dict[int, Symbol] = dict()

        def get_sym(addr):
            if addr in addr_to_sym:
                return addr_to_sym[addr]
            
            try:
                sym = self.angr_mgr.get_sym(addr)
            except ValueError:
                sym = None
            addr_to_sym[addr] = sym
            return sym

        last_callstack:List[int] = list()
        last_callstack_syms:List[Symbol] = list()

        for l in Pbar("finding symbols", items=trace):
            callstack_syms = []
            if 'to_ip' not in l or l.get('type') != 'func':
                continue
            to_sym = get_sym(l['to_ip'])
            from_sym = get_sym(l['from_ip'])

            if to_sym is not None and from_sym is not None:
                callstack = [l['to_ip'], l['from_ip']]
                callstack_syms = [to_sym, from_sym]

            # TODO: Consider whether we actually save the callstack on return
            if 'callstack' not in l or l['callstack'] is None:
                continue

            # The callstack is really dirty: There is some junk of ftrace on top
            # of to_sym in callstack_sym. Get rid of it.  Then the from entry is
            # not always there, so we need to check whether to skip it.
            skip:Optional[str] = "to"
            for callstack_entry in l['callstack']:
                sym = callstack_entry and get_sym(callstack_entry)

                if skip == "to":
                    if sym == to_sym:
                        skip = "from"
                    continue
                if skip == "from":
                    skip = None
                    if sym == from_sym:
                      continue

                callstack.append(callstack_entry)
                callstack_syms.append(sym)

            # Guess the symbols and the addresses we did not figure out from the last stack
            for i, v in enumerate(reversed(callstack)):
                if v is None and i < len(last_callstack):
                    callstack[-i-1] = last_callstack[-i-1]
                    callstack_syms[-i-1] = last_callstack_syms[-i-1]

            last_callstack_syms = callstack_syms
            last_callstack = callstack

            l['callstack_syms'] = callstack_syms
            l['callstack'] = callstack
        return trace

    def wait_for_syscall(self, process:Optional[PtraceProcess]) -> Optional[PtraceSyscall]:
        while len(self.dbg.list) != 0:
            process_filter = [process] if process is not None else self.dbg.list
            stopped = filter(lambda p: p.is_stopped, process_filter)
            for p in stopped:
                signum = 0
                if len(self.pending_signals[p.pid]) != 0:
                    signum = self.pending_signals[p.pid].popleft()
                try:
                    p.syscall(signum)
                except (ptrace.debugger.ProcessExit, ptrace.PtraceError) as exc:
                    pr_msg(f"error waiting for syscall failure {exc}", level="WARN")

            signum = 0
            is_syscall = False

            trapped_process: PtraceProcess

            try:
                e = self.dbg.waitSyscall()
                is_syscall = True
                trapped_process = e.process
            except ptrace.debugger.ProcessExit as e:
                e.process.processExited(e)
                trapped_process = e.process
            except ptrace.debugger.ProcessSignal as e:
                self.pending_signals[e.process.pid].append(e.signum)
                trapped_process = e.process
            except ptrace.debugger.NewProcessEvent as e:
                e.process.parent.is_stopped = True
                trapped_process = e.process
            except ptrace.debugger.ProcessExecution as e:
                # It should have been marked as stopped, but it is not
                e.process.is_stopped = True
                trapped_process = e.process

            if not is_syscall:
                continue

            if process_filter and trapped_process not in process_filter:
                # TODO: queue the process to be resumed or analyzed later, since
                # otherwise we might miss failures
                continue
            
            try:
                syscall = trapped_process.syscall_state.event(ptrace.func_call.FunctionCallOptions())
            except (ptrace.debugger.ProcessExit, ptrace.PtraceError) as exc:
                pr_msg(f'error getting syscall info: {exc}', level='WARN')
                continue

            # For syscall entry, the result is None
            if syscall.result is None:
                continue

            # On reproduction, process is not None and we do not care about the
            # result and the syscall. (There might be some strange scenario that
            # we do if some signal is involved, but ignore it.)
            if process is None:
                if self.syscall_filter is not None and self.syscall_filter != syscall.syscall:
                    continue

                if (syscall.result >= 0 or
                    (self.errcode_filter and self.errcode_filter != -syscall.result)):
                    continue

                self.occurrences += 1
                if self.occurrences_filter is not None and self.occurrences not in self.occurrences_filter:
                    continue

            return syscall

        return None

    def remove_snapshot_irqs(self, snapshot:List[Dict]) -> List[Dict]:
        """
        Removes all IRQ-related events from a given snapshot, including all
        events between an irqenter event and its corresponding irqexit event.
        
        :param snapshot: A list of dictionaries representing events in the snapshot.
        :return: The input snapshot with all IRQ-related events removed.
        """
        irq_depth = 0
        filtered_snapshot = []
        for event in Pbar("remove irqs", snapshot):
            if event['type'] == 'irqenter':
                irq_depth += 1
            elif event['type'] == 'irqexit':
                irq_depth -= 1
            elif irq_depth == 0:
                filtered_snapshot.append(event)
        return filtered_snapshot

    def analyze_probe_insns(self, sym:Symbol) -> Set[CsInsn]:
        assert self.angr_mgr is not None

        def collect(sym: Symbol, insn:CsInsn, **kwargs):
            assert self.angr_mgr is not None

            # Do not put probes on the first instruction of a function, as we
            # have already set a probe on the function.
            insns = kwargs['insns']
            if (arch.is_predicated_mov(insn) or arch.is_cond_branch_insn(insn) or
                arch.is_rep_insn(insn)):
                insns.add(insn)

            if arch.is_rep_insn(insn):
                # For rep-prefix, we need to trace the counter on the following
                # instruction to figure out how many iterations were executed.
                insns.add(self.angr_mgr.next_insn(insn))
            if arch.is_indirect_branch_target(insn):
                # We cannot put a probe point on the ENDBRxx instructions. Instead
                # put on the next one. Anyhow, we do not care about the first instruction
                # in a symbol.
                if (insn.address != self.angr_mgr.get_sym_addr(sym) or
                    not Ftrace.is_available_filter_function(sym)):
                    insns.add(self.angr_mgr.next_insn(insn))
            elif arch.is_direct_call_insn(insn):
                # On calls to functions that cannot be probed, keep the return
                # value. We will create an artifical fork based on the return
                # value if the return value is the error code.
                tgt = arch.get_direct_branch_target(insn)
                try:
                    tgt_sym = self.angr_mgr.get_sym(tgt)
                except:
                    tgt_sym = None

                if (tgt_sym is None or
                    (tgt_sym.name not in self.NORETURN_FUNCS and
                    not Ftrace.is_available_filter_function(tgt_sym))):
                    try:
                        insns.add(self.angr_mgr.next_insn(insn))
                    except:
                        pass
            elif arch.is_indirect_call_insn(insn):
                # We might not have the callee as instrumentable. We would add the next
                # instruction to the probe list. It would have been better to figure out
                # from the trace whether we can actually trace without this probe point.
                insns.add(self.angr_mgr.next_insn(insn))
        
        insns:Set[CsInsn] = set()
        self.angr_mgr.for_each_insn_in_sym(sym, collect, insns=insns)
        return insns

    # Returns addresses of probes, set of symbols to trace entry, set of symbols
    # to simulate.
    def tracking_probe_addrs(self, syms:Set[Symbol]) -> Tuple[Set[int], Set[Symbol]]:
        probe_syms:Set[Symbol] = set()
        probe_insns:Set[CsInsn] = set()

        for sym in Pbar("find probe points", syms, unit="symbol"):
            if self.is_invalid_func_probe(sym):
                pr_msg(f"cannot set func probe on {sym.name}", level="DEBUG")
                continue

            insns = self.analyze_probe_insns(sym)
            cannot_probe = {insn.address for insn in insns if self.is_invalid_probe(insn)}
            if len(cannot_probe) == 0:
                probe_insns |= insns
                probe_syms.add(sym)
            else:
                cannot_probe_first = next(iter(cannot_probe))
                cannot_probe_addr = (cannot_probe_first if isinstance(cannot_probe_first, int)
                                    else cannot_probe_first.address)
                pr_msg(f"cannot set probe on {sym.name} (e.g., {hex(cannot_probe_addr)})", level="DEBUG")

        probe_addrs = {insn.address for insn in probe_insns} - {sym.rebased_addr for sym in probe_syms}
        return (probe_addrs, probe_syms)

    def invalid_func_probe_cause(self, sym: Symbol) -> Optional[str]:
        assert self.angr_mgr is not None

        ftrace = Ftrace.main_instance()

        if sym is None:
            return 'none'
        if not ftrace.is_available_filter_function(sym):
            return 'func blacklisted'
        if self.angr_mgr.is_noprobe_sym(sym):
            return 'discarded'
        return None
    
    def is_invalid_func_probe(self, sym: Symbol) -> bool:
        return self.invalid_func_probe_cause(sym) is not None

    def is_invalid_probe(self, insn: CsInsn) -> Optional[str]:
        addr = insn.address

        # Detect UD2: cannot set kprobes
        if insn.bytes == b'\x0f\x0b':
            return 'bug'

        # Indirect jumps cannot be patched (possibly due to spectre)
        if arch.is_indirect_jmp_insn(insn):
            return "indirect-jmp"

        # Check if the address is blacklisted in ftrace
        ftrace = Ftrace.main_instance()
        if ftrace.main_instance().is_kprobe_blacklisted(addr):
            return 'blacklisted'

        # Check if the address is invalid for kprobe (e.g., static key/call)
        if ftrace.is_invalid_kprobe_addr(addr):
            return 'invalid'

        # If none of the conditions above are met, the probe is valid
        return None