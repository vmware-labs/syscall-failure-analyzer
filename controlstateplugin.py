# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import angr
import capstone
import copy
from typing import Any, Dict, List, Optional

from arch import arch

class ControlStatePlugin(angr.SimStatePlugin):
    STEP_TIMEOUT: int = 10

    def __init__(self, angr_mgr, detailed_trace:bool, branches:List[Dict], done_branches:int):
        super(ControlStatePlugin, self).__init__()
        self.done_branches = done_branches
        self.branches:List[Dict] = branches
        self.backtracking = False
        self.max_depth = 0x10000    # Just if something goes wrong
        self.stop_depth = 0
        self.last_depth = None
        # Save whether the trace is detailed and includes REP instructions and predicated moves
        self.detailed_trace = detailed_trace
        self.only_symbols = None
        self.__last_insn = None
        self.diverged = False
        self.expected_ip:Optional[int] = None
        self.in_simulated = True
        self.no_callees = False
        self.angr_mgr = angr_mgr
        self.arch = arch.controlStatePluginArch()

    @angr.SimStatePlugin.memo
    def copy(self, memo) -> 'ControlStatePlugin':
        c = copy.copy(self)
        c.arch = copy.copy(self.arch)
        return c

    @property
    def current_branch(self) -> Optional[Dict[str, Any]]:
        assert not self.backtracking
        return None if len(self.branches) == 0 else self.branches[0]

    def match_src(self) -> bool:
        br = self.current_branch
        return br is not None and self.last_insn is not None and br['from_ip'] == self.last_insn.address
    
    def update(self, s:angr.SimState):
        ip = self.angr_mgr.state_ip(s)
        self.__last_insn = None if ip is None else self.angr_mgr.get_insn(ip)

    @property
    def last_insn(self) -> capstone.CsInsn:
        return self.__last_insn

    def trace_finished(self) -> bool:
        return len(self.branches) == 0

    def next_branch(self) -> bool:
        if self.trace_finished():
            return False
        self.branches = self.branches[1:]
        self.done_branches += 1
        return not self.trace_finished()

