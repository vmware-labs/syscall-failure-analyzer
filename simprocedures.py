# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import inspect
from typing import Optional, Set, Type, Tuple
import angr
from controlstateplugin import ControlStatePlugin
from arch import arch
import capstone

def state_ip(s:angr.SimState) -> Optional[int]:
    v = s.registers.load(arch.ip_reg_name)
    try:
        return s.solver.eval_one(v)
    except angr.SimValueError:
        return None

def track_to_ret(proc: angr.SimProcedure):
    state = proc.state
    control = state.control
    assert isinstance(control, ControlStatePlugin)

    if control.backtracking:
        return

    ip = state_ip(state)
    assert(ip is not None)
    # TODO: Check if we need better way
    ret_ip = state.callstack.ret_addr
    assert(ret_ip is not None and ret_ip != 0)
    # TODO: let the arch give the address width
    if ret_ip < 0:
        ret_ip += 1 << arch.address_width

    br = control.current_branch
    while br is not None and br['to_ip'] != ret_ip:
        control.next_branch()
        br = control.current_branch

    if br is None:
        # We would not be able to return to the correct address
        control.diverged = True
        control.expected_ip = None
    else:
        br.update({
            'from_ip': None,
            'from_sym': None,
            'from_offset': None
        })

def track_out_of_syms(proc: angr.SimProcedure, sym_names:Set[str]):
    state = proc.state
    control = state.control
    assert isinstance(control, ControlStatePlugin)

    if control.backtracking:
        return

    ip = state_ip(state)
    assert(ip is not None)

    br = control.current_branch
    while br is not None and br['from_ip'] in sym_names:
        control.next_branch()
        br = control.current_branch

    if br is None:
        control.diverged = True
        control.expected_ip = None

class CopyProcedure(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        track_to_ret(self)
        copied = self.state.solver.BVS('copied', 64)
        self.state.add_constraints(copied >= 0)
            
        if False and 'unconstrained' in str(limit):
            old_limit = limit
            limit = self.state.solver.BVS('limit', arch.address_width)
            self.state.add_constraints(old_limit == limit)

        self.state.add_constraints(limit <= self.state.libc.max_memcpy_size)
        #self.state.add_constraints(copied <= self.state.libc.max_memcpy_size)
        self.state.add_constraints(copied <= limit)

        if not self.state.solver.is_true(copied == 0):
            src_mem = self.state.memory.load(src_addr, copied, endness='Iend_LE')
            self.state.memory.store(dst_addr, src_mem, size=copied, endness='Iend_LE')

        self.ret(limit - copied)

    def __rept__(self) -> str:
        return 'CopyProcedure'

class ReturnProcedure(angr.SimProcedure):
    def __init__(self):
        super(ReturnProcedure, self).__init__()

    def run(self):
        control = self.state.control
        assert isinstance(control, ControlStatePlugin)

        if control.backtracking:
            self.ret()
        
        track_out_of_syms(self, {'zen_untrain_ret', '__x86_return_thunk'})
        if control.diverged:
            return None
        
        # Force the correct return address
        self.ret_to = control.current_branch['to_ip']
        r = self.ret()
        self.ret_to = None
        control.next_branch()
        return r

class ProcedureWrapper(angr.SimProcedure):
    def __init__(self, proc_class:Type[angr.SimProcedure], limits:Optional[Tuple[Optional[int], Optional[int]]]=None):
        super(ProcedureWrapper, self).__init__()
        self.proc_class = proc_class
        sig = inspect.signature(proc_class.run)
        self.n_parameters = len(sig.parameters) - 1
        self.limits = limits and enumerate(limits)

    def run(self):
        # Collect arguments from the state registers according to the calling convention
        track_to_ret(self)

        cc = self.state.project.factory.cc()
        args = cc.ARG_REGS

        # Fetch arguments from the registers
        arg_values = [self.state.registers.load(reg) for reg in args][:self.n_parameters]

        if self.limits:
            for i, (min_val, max_val) in self.limits:
                if min_val is None and max_val is None:
                    continue

                val = arg_values[i]
                if max_val is not None:
                    self.state.add_constraints(val <= max_val)
                if min_val is not None:
                    self.state.add_constraints(val >= min_val)

        # call the procedure with the fetched arguments
        result = self.inline_call(self.proc_class, *arg_values).ret_expr
        if result.length == arch.address_width:
            return result
        
        return result.sign_extend(arch.address_width - result.length)

class RepHook(angr.exploration_techniques.tracer.RepHook):
    def __init__(self, mnemonic):
        super().__init__(mnemonic.split(" ")[1])

    def trace_to_next(self, state):
        c = state.control
        assert isinstance(c, ControlStatePlugin)
        if not c.backtracking:
            addr = state.addr
            br = c.current_branch
            while br is not None and br['from_ip'] == addr and br['to_ip'] == addr:
                c.next_branch()
                br = c.current_branch

    def run(self, state, procedure=None, *arguments, **kwargs):
        self.trace_to_next(state)

        if procedure is not None:
            result = self._inline_call(state, procedure, *arguments, **kwargs)
            print(f'Result of inline call: {result}')

        
        # Invoke the run() method from the parent class
        super().run(state)

# TODO: Move to AngrSim
class RetpolineProcedure(angr.SimProcedure):
    def __init__(self, reg: str):
        super(RetpolineProcedure, self).__init__()
        self.reg = reg

    def run(self):
        state = self.state
        reg = getattr(state.regs, self.reg)
        control = state.control

        if control.backtracking:
            return self.jump(reg)

        trace_from_ip = control.current_branch['from_ip']
        trace_to_ip = control.current_branch['to_ip']
        control.expected_ip = trace_to_ip
        angr_mgr = control.angr_mgr

        current_state_ip = state_ip(state)

        def in_retpoline(ip:int) -> bool:
            sym_name = angr_mgr.get_sym_name(ip)
            return (sym_name.startswith('__x86_indirect_thunk') or 
                    sym_name in {'__x86_return_thunk', 'zen_untrain_ret'})
 
        if current_state_ip == trace_from_ip:
            # TODO: Handle the case in which the trace ends with a retpoline
            while in_retpoline(trace_to_ip):
                control.next_branch()
                trace_to_ip = control.current_branch['to_ip']
                trace_from_ip = control.current_branch['from_ip']
                if not in_retpoline(trace_from_ip):
                    control.diverged = True
                    break
            control.expected_ip = trace_to_ip
        else:
            control.diverged = True

        if not control.diverged:
            state.add_constraints(reg == trace_to_ip)
            control.next_branch()
            return self.jump(trace_to_ip)

        return self.jump(reg)