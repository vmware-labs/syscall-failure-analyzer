# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import capstone
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, Callable, Union
import angr
import claripy
import copy
import struct

from cle.backends import Symbol
from abc import ABC, abstractmethod
from abstractarch import Arch, ControlStatePluginArch


class ControlStatePluginX86(ControlStatePluginArch):
    def __init__(self):
        super().__init__()
        self.eflags_if = True

    def copy(self) -> 'ControlStatePluginX86':
        return copy.copy(self)

class ArchX86(Arch):
    X86_EFLAGS_CF = 0x0001
    X86_EFLAGS_PF = 0x0004
    X86_EFLAGS_AF = 0x0010
    X86_EFLAGS_ZF = 0x0040
    X86_EFLAGS_SF = 0x0080
    X86_EFLAGS_OF = 0x0800
    X86_EFLAGS_IF = 0x0200

    STACK_SIZE = 8
    STACK_END = 0xffffeb0000000000
    SYSCALL_INSN_LEN = 2

    @property
    def stack_end(self) -> int:
        return self.STACK_END

    @property
    def syscall_insn_len(self) -> int:
        return self.SYSCALL_INSN_LEN

    retpoline_thunk_regs = { 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15' }

    __irq_exit_sym_names = {'native_irq_return_iret', 'asm_exc_nmi', 'nmi_restore'}

    flags_cond_map = {
        # Checked flags, Invert
        capstone.x86.X86_INS_JAE: (X86_EFLAGS_CF, True),
        capstone.x86.X86_INS_JA: (X86_EFLAGS_CF|X86_EFLAGS_ZF, True),
        capstone.x86.X86_INS_JBE: (X86_EFLAGS_CF|X86_EFLAGS_ZF, False),
        capstone.x86.X86_INS_JB: (X86_EFLAGS_CF, False),
        capstone.x86.X86_INS_JE: (X86_EFLAGS_ZF, False),
        capstone.x86.X86_INS_JNE: (X86_EFLAGS_ZF, True),
        capstone.x86.X86_INS_JNO: (X86_EFLAGS_OF, True),
        capstone.x86.X86_INS_JNP: (X86_EFLAGS_PF, True),
        capstone.x86.X86_INS_JNS: (X86_EFLAGS_SF, True),
        capstone.x86.X86_INS_JO: (X86_EFLAGS_OF, False),
        capstone.x86.X86_INS_JP: (X86_EFLAGS_PF, False),
        capstone.x86.X86_INS_JS: (X86_EFLAGS_SF, False),
    }

    predicated_map = {
        capstone.x86.X86_INS_SETAE: capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_SETA: capstone.x86.X86_INS_JA,
        capstone.x86.X86_INS_SETBE: capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_SETB: capstone.x86.X86_INS_JB,
        capstone.x86.X86_INS_SETE: capstone.x86.X86_INS_JE,
        capstone.x86.X86_INS_SETGE: capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_SETG: capstone.x86.X86_INS_JG,
        capstone.x86.X86_INS_SETLE: capstone.x86.X86_INS_JLE,
        capstone.x86.X86_INS_SETL: capstone.x86.X86_INS_JL,
        capstone.x86.X86_INS_SETNE: capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_SETNO: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_SETNP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_SETNS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_SETO: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_SETP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_SETS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_CMOVAE: capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_CMOVA: capstone.x86.X86_INS_JA,
        capstone.x86.X86_INS_CMOVBE: capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_CMOVB: capstone.x86.X86_INS_JB,
        capstone.x86.X86_INS_CMOVE: capstone.x86.X86_INS_JE,
        capstone.x86.X86_INS_CMOVGE: capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_CMOVG: capstone.x86.X86_INS_JG,
        capstone.x86.X86_INS_CMOVLE: capstone.x86.X86_INS_JLE,
        capstone.x86.X86_INS_CMOVL: capstone.x86.X86_INS_JL,
        capstone.x86.X86_INS_CMOVNE: capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_CMOVNO: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_CMOVNP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_CMOVNS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_CMOVO: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_CMOVP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_CMOVS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_SBB: capstone.x86.X86_INS_JB,
    }

    cx_cond_map = {
        capstone.x86.X86_INS_JCXZ: 0xffff,
        capstone.x86.X86_INS_JECXZ: 0xffffffff,
        capstone.x86.X86_INS_JRCXZ: 0xffffffffffffffff,
    }

    cs_to_pyvex_reg_map = {
        capstone.x86.X86_REG_AH: 'ah',
        capstone.x86.X86_REG_RAX: 'rax',
        capstone.x86.X86_REG_RDX: 'rdx',
        capstone.x86.X86_REG_EFLAGS: 'eflags',
        capstone.x86.X86_REG_AL : 'al',
        capstone.x86.X86_REG_AX : 'ax',
        capstone.x86.X86_REG_BH : 'bh',
        capstone.x86.X86_REG_BL : 'bl',
        capstone.x86.X86_REG_BP : 'bp',
        capstone.x86.X86_REG_BPL : 'bpl',
        capstone.x86.X86_REG_AX: 'ax',
        capstone.x86.X86_REG_BX : 'bx',
        capstone.x86.X86_REG_CH : 'ch',
        capstone.x86.X86_REG_CL : 'cl',
        capstone.x86.X86_REG_CS : 'cs',
        capstone.x86.X86_REG_CX : 'cx',
        capstone.x86.X86_REG_DH : 'dh',
        capstone.x86.X86_REG_DI : 'di',
        capstone.x86.X86_REG_DIL : 'dil',
        capstone.x86.X86_REG_DL : 'dl',
        capstone.x86.X86_REG_DS : 'ds',
        capstone.x86.X86_REG_DX : 'dx',
        capstone.x86.X86_REG_EAX : 'eax',
        capstone.x86.X86_REG_EBP : 'ebp',
        capstone.x86.X86_REG_EBX : 'ebx',
        capstone.x86.X86_REG_ECX : 'ecx',
        capstone.x86.X86_REG_EDI : 'edi',
        capstone.x86.X86_REG_EDX : 'edx',
        capstone.x86.X86_REG_EFLAGS : 'eflags',
        capstone.x86.X86_REG_EIP : 'eip',
        capstone.x86.X86_REG_EIZ : 'eiz',
        capstone.x86.X86_REG_ES : 'es',
        capstone.x86.X86_REG_ESI : 'esi',
        capstone.x86.X86_REG_ESP : 'esp',
        capstone.x86.X86_REG_FS : 'fs',
        capstone.x86.X86_REG_GS : 'gs',
        capstone.x86.X86_REG_IP : 'ip',
        capstone.x86.X86_REG_RAX : 'rax',
        capstone.x86.X86_REG_RBP : 'rbp',
        capstone.x86.X86_REG_RBX : 'rbx',
        capstone.x86.X86_REG_RCX : 'rcx',
        capstone.x86.X86_REG_RDI : 'rdi',
        capstone.x86.X86_REG_RDX : 'rdx',
        capstone.x86.X86_REG_RIP : 'rip',
        capstone.x86.X86_REG_RIZ : 'riz',
        capstone.x86.X86_REG_RSI : 'rsi',
        capstone.x86.X86_REG_RSP : 'rsp',
        capstone.x86.X86_REG_SI : 'si',
        capstone.x86.X86_REG_SIL : 'sil',
        capstone.x86.X86_REG_SP : 'sp',
        capstone.x86.X86_REG_SPL : 'spl',
        capstone.x86.X86_REG_SS : 'ss',
    }

    def cs_to_pyvex_reg(self, reg:int) -> str:
        return self.cs_to_pyvex_reg_map[reg]

    @property
    def pointer_size(self) -> int:
        return 8

    @property
    def arch_name(self) -> str:
        return "amd64"

    @property
    def default_text_base(self) -> int:
        return 0xffffffff81000000

    @property
    def syscall_entry_points(self) -> Set[str]:
        #return {'entry_SYSCALL_64', 'entry_SYSCALL_64_after_hwframe'}
        return {'do_syscall_64'}
    
    def controlStatePluginArch(self) -> ControlStatePluginX86:
        return ControlStatePluginX86()

    # Returns two states following a cmov constraint. The first is the one that
    # actually took place, and the second one is the one was not followed.
    def predicated_mov_constraint(self, state:angr.SimState, cond_true:bool, insn:capstone.CsInsn) -> List[angr.SimState]:

        def ffs(x:int) -> int:
            """Returns the index, counting from 0, of the
            least significant set bit in `x`.
            """
            return (x&-x).bit_length()-1

        def flags_equal(flags, flag_a:int, flag_b:int) -> bool:
            offset_a, offset_b = ffs(flag_a), ffs(flag_b)
            return flags[offset_a] == flags[offset_b]

        # Creating a list of taken, not-taken
        successors = list()

        flags = state.regs.eflags
        id = self.predicated_map[insn.id]
        simple_mask, simple_mask_clear, single_bit_cond = None, False, False
        if id in self.flags_cond_map:
            mask, invert = self.flags_cond_map[id]
            constraint = (flags & mask) != 0
            if invert:
                constraint = claripy.Not(constraint)#) if cond[1] else flags & cond[0]
            single_bit_cond = (mask & (mask - 1)) == 0
            simple_mask, simple_mask_clear = mask, invert
        elif id == capstone.x86.X86_INS_JGE:
            constraint = flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF)
        elif id == capstone.x86.X86_INS_JG:
                constraint = claripy.And((flags & self.X86_EFLAGS_ZF) == 0,
                        flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF))
        elif id == capstone.x86.X86_INS_JLE:
            constraint = claripy.Or((flags & self.X86_EFLAGS_ZF) != 0,
                    claripy.Not(flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF)))
        elif id == capstone.x86.X86_INS_JL:
            constraint = flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF)
        else:
            raise Exception("Unhandled condition")

        for sim_cond_true in [True, False]:
            n = state.copy()
            n.add_constraints(constraint if sim_cond_true else claripy.Not(constraint))

            # Try to set the flags to simplify execution if we can figure out the flags
            if simple_mask is not None:
                # if they are not equal, the bit is cleared
                if sim_cond_true == simple_mask_clear:
                    n.regs.flags = flags & ~simple_mask
                elif single_bit_cond:
                    n.regs.flags = flags | simple_mask

            n.control.diverged = cond_true != sim_cond_true
            n.control.expected_ip = state.solver.eval_one(state.addr)

            successors.append(n)

        return successors

    def is_cond_jmp_taken(self, insn:capstone.CsInsn, state:Dict[str, Any]) -> bool:
        def flags_equal(flags:int, flag_a:int, flag_b:int) -> bool:
            return ((flags & flag_a) != 0) == ((flags & flag_b) != 0)

        flags = state['flags']
        id = self.predicated_map.get(insn.id, insn.id)

        if id in self.flags_cond_map:
            cond = self.flags_cond_map[id]
            r = flags & cond[0] == 0
            return r if cond[1] else not r
        if id in self.cx_cond_map:
            # TODO: It just never happended and should be checked once
            assert 0 == 1
            return state['cx'] & self.cx_cond_map[id] != 0
        if id == capstone.x86.X86_INS_JGE:
            return flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF)
        if id == capstone.x86.X86_INS_JG:
            return ((flags & self.X86_EFLAGS_ZF) == 0 and
                    flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF))
        if id == capstone.x86.X86_INS_JLE:
            return ((flags & self.X86_EFLAGS_ZF) != 0 or
                    not flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF))
        if id == capstone.x86.X86_INS_JL:
            return not flags_equal(flags, self.X86_EFLAGS_SF, self.X86_EFLAGS_OF)

        raise Exception('Unhandled condition')

    def rep_iterations(self, insn:capstone.CsInsn, state:Dict) -> int:
        return state['cx'] & ((1 << (insn.operands[0].size * 8)) - 1)

    def is_rep_taken(self, insn:capstone.CsInsn, state:Dict) -> bool:
        # We would assume only one rep prefix as proper code
        rep_prefix = [prefix for prefix in insn.prefix if prefix in {
            capstone.x86.X86_PREFIX_REPE,
            capstone.x86.X86_PREFIX_REPNE,
            capstone.x86.X86_PREFIX_REP,
        }][0]

        if self.rep_iterations(insn, state) == 0:
            return False

        if rep_prefix == capstone.x86.X86_PREFIX_REPNE:
            return state['flags'] & self.X86_EFLAGS_ZF == 0
        if rep_prefix == capstone.x86.X86_PREFIX_REPE:
            return state['flags'] & self.X86_EFLAGS_ZF != 0

        assert(rep_prefix == capstone.x86.X86_PREFIX_REP)
        return True

    @property
    def ftrace_state_str(self) -> str:
        return 'flags=%flags cx=%cx ax=%ax'
    
    def ftrace_state_dict(self, d:Dict[str, Any]) -> Dict[str, Any]:
        return {
            'flags': d['flags'],
            'cx': d['cx'],
        }

    def is_loop_taken(self, insn:capstone.CsInsn, state:Dict[str, Any]) -> bool:
        flags, rcx = state['flags'], state['cx']

        if (rcx & (1 << (insn.operands[0].size * 8)) - 1) == 0:
            return False

        if insn.id == capstone.x86.X86_INS_LOOPNE:
            return flags & self.X86_EFLAGS_ZF == 0
        if insn.id == capstone.x86.X86_INS_LOOPE:
            return flags & self.X86_EFLAGS_ZF != 0

        assert(insn.id == capstone.x86.X86_INS_LOOP)
        return True

    def is_predicated_mov(self, insn) -> bool:
        # cannot just check the group, since SETxx does not have a group
        return insn.id in self.predicated_map

    def is_rep_insn(self, insn) -> bool:
        return (not {capstone.x86.X86_PREFIX_REP, capstone.x86.X86_PREFIX_REPE, 
                 capstone.x86.X86_PREFIX_REPNE}.isdisjoint(insn.prefix))

    def is_fixed_rep_insn(self, insn) -> bool:
        return (insn.mnemonic.startswith("rep m") or
               insn.mnemonic.startswith("rep s"))

    def is_branch_insn(self, insn) -> bool:
            return ((not {capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                 capstone.CS_GRP_JUMP}.isdisjoint(insn.groups)) or
                 self.is_rep_insn(insn) or self.is_loop_insn(insn))

    def is_jmp_insn(self, insn) -> bool:
        return capstone.x86.X86_GRP_JUMP in insn.groups

    def is_indirect_jmp_insn(self, insn) -> bool:
        return (self.is_jmp_insn(insn) and
                insn.id in {capstone.x86.X86_INS_LJMP,
                            capstone.x86.X86_INS_JMP} and
                insn.operands[0].type != capstone.x86.X86_OP_IMM)

    def is_indirect_branch_target(self, insn) -> bool:
        return insn.id in {capstone.x86.X86_INS_ENDBR32,
                           capstone.x86.X86_INS_ENDBR64}

    def is_indirect_branch_insn(self, insn) -> bool:
        return (self.is_indirect_jmp_insn(insn) or
                self.is_indirect_call_insn(insn))

    def __is_ret_insn(self, insn:capstone.CsInsn) -> bool:
        return capstone.x86.X86_GRP_RET in insn.groups

    def is_ret_insn(self, insn:capstone.CsInsn) -> bool:
        if self.__is_ret_insn(insn):
            return True

        # Detect retthunks as effectively ret instructions
        if self.is_direct_jmp_insn(insn):
            target = self.get_direct_branch_target(insn)
            return target == self.return_thunk_addr

        return False

    def is_call_insn(self, insn:capstone.CsInsn) -> bool:
        return capstone.x86.X86_GRP_CALL in insn.groups
    
    def is_cond_jmp_insn(self, insn:capstone.CsInsn) -> bool:
        return (capstone.x86.X86_GRP_JUMP in insn.groups and
                insn.id not in {capstone.x86.X86_INS_LJMP,
                            capstone.x86.X86_INS_JMP})

    def is_loop_insn(self, insn:capstone.CsInsn) -> bool:
        return insn.id in (capstone.x86.X86_INS_LOOP,
                            capstone.x86.X86_INS_LOOPNE,
                            capstone.x86.X86_INS_LOOPE)

    def is_cond_branch_insn(self, insn:capstone.CsInsn) -> bool:
        return (self.is_cond_jmp_insn(insn) or self.is_rep_insn(insn) or
                self.is_loop_insn(insn))

    def is_direct_call_insn(self, insn:capstone.CsInsn) -> bool:
        return (self.is_call_insn(insn) and
                insn.operands[0].type == capstone.x86.X86_OP_IMM)
    
    def is_direct_branch_insn(self, insn:capstone.CsInsn) -> bool:
        return self.is_direct_jmp_insn(insn) or self.is_direct_call_insn(insn)

    def get_direct_branch_target(self, insn:capstone.CsInsn) -> int:
        if self.is_rep_insn(insn):
            return insn.address
        return int(insn.op_str, 16)

    @staticmethod
    def get_control_state_arch(state:angr.SimState) -> 'ControlStatePluginX86':
        # To avoid circular import, we could have used lazy import
        return state.control.arch # type: ignore

    @staticmethod
    def sti_hook(state:angr.SimState):
        archX86 = ArchX86.get_control_state_arch(state)
        archX86.eflags_if = True

    @staticmethod
    def cli_hook(state:angr.SimState):
        archX86 = ArchX86.get_control_state_arch(state)
        archX86.eflags_if = False

    @staticmethod
    def __popf_hook(state:angr.SimState, reg:str):
        archX86 = ArchX86.get_control_state_arch(state)
        rsp = state.registers.load('rsp')
        v = state.memory.load(rsp, size=8, endness='Iend_LE')
        state.registers.store(reg, v)
        archX86.eflags_if = (v & arch.X86_EFLAGS_IF) != 0
        rsp += ArchX86.STACK_SIZE
        state.registers.store('rsp', rsp)

    @staticmethod
    def popf_hook(state:angr.SimState):
        ArchX86.__popf_hook(state, "flags")
    
    @staticmethod
    def popfd_hook(state:angr.SimState):
        ArchX86.__popf_hook(state, "eflags")
         
    @staticmethod
    def popfq_hook(state:angr.SimState):
        ArchX86.__popf_hook(state, "rflags")

    @staticmethod
    def __pushf_hook(state:angr.SimState, reg:str):
        archX86 = ArchX86.get_control_state_arch(state)
        rsp = state.registers.load('rsp')
        rsp -= ArchX86.STACK_SIZE
        v = state.registers.load(reg)
        if archX86.eflags_if:
            v |= arch.X86_EFLAGS_IF

        state.memory.store(rsp, v, size=8, endness='Iend_LE')
        state.registers.store('rsp', rsp)

    @staticmethod
    def pushf_hook(state:angr.SimState):
        ArchX86.__pushf_hook(state, "flags")
    
    @staticmethod
    def pushfd_hook(state:angr.SimState):
        ArchX86.__pushf_hook(state, "eflags")
         
    @staticmethod
    def pushfq_hook(state:angr.SimState):
        ArchX86.__pushf_hook(state, "rflags")

    @staticmethod
    def skip_mask_hook(state:angr.SimState):
        #insn = angr_mgr.state_insn(state)
        insn = state.control.angr_mgr.state_insn(state) # type: ignore

        for reg in insn.regs_write:
            reg_name = arch.cs_to_pyvex_reg(reg)
            val = state.registers.load(reg_name)
            v = state.solver.Unconstrained("unconstrained_val", val.length)
            # TODO: find width and create correct value
            state.registers.store(reg_name, v)

    @property
    def per_cpu_reg(self) -> str:
        return 'gs'

    @property
    def per_cpu_offset(self) -> int:
        return 0x833e8000
    
    @property
    def stack_reg(self) -> str:
        return 'rsp'
         
    def pyvex_workaround(self, insn:capstone.CsInsn) -> Tuple[Union[Callable, None],  bool]:
        # MOV x, SREG
        if insn.bytes[0] == 0x8e:
            return self.skip_mask_hook, True

        # RDPKRU
        if insn.bytes[0:3] == b'\x0f\x01\xee':
            return self.skip_mask_hook, True
            
        if insn.id in {capstone.x86.X86_INS_WRFSBASE,
                    capstone.x86.X86_INS_WRGSBASE,
                    capstone.x86.X86_INS_STAC,
                    capstone.x86.X86_INS_CLAC,
                    capstone.x86.X86_INS_INVLPG,
                    capstone.x86.X86_INS_INVLPGA,
                    capstone.x86.X86_INS_INVPCID,
                    capstone.x86.X86_INS_INVEPT,
                    capstone.x86.X86_INS_SGDT,
                    capstone.x86.X86_INS_LGDT,
                    capstone.x86.X86_INS_IDIV,
                    capstone.x86.X86_INS_UD0,
                    capstone.x86.X86_INS_UD2B,
                    capstone.x86.X86_INS_SWAPGS,
                    capstone.x86.X86_INS_WRMSR,
                    capstone.x86.X86_INS_RDMSR,
                    capstone.x86.X86_INS_VERW,
                    }:
            return self.skip_mask_hook, True

        hooks = {capstone.x86.X86_INS_STI: self.sti_hook,
                 capstone.x86.X86_INS_CLI: self.cli_hook,
                 capstone.x86.X86_INS_PUSHF: self.pushf_hook,
                 capstone.x86.X86_INS_PUSHFD: self.pushfd_hook,
                 capstone.x86.X86_INS_PUSHFQ: self.pushfq_hook,
                 capstone.x86.X86_INS_POPF: self.popf_hook,
                 capstone.x86.X86_INS_POPFD: self.popfd_hook,
                 capstone.x86.X86_INS_POPFQ: self.popfq_hook,
                 }

        if insn.id in hooks:
            return hooks[insn.id], False

        return None, False

    def nop_insn(self, size:int) -> bytes:
        return b'\x90' * size

    def init_capstone(self) -> capstone.Cs:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    @property
    def ret_reg_name(self) -> str:
        return 'rax'

    @property 
    def stack_related_reg_names(self) -> List[str]:
        return ['rsp', 'rbp']

    @property
    def ip_reg_name(self) -> str:
        return 'rip'

    def is_iret_insn(self, insn:capstone.CsInsn) -> bool:
        return (insn.id == capstone.x86.X86_INS_IRET or
                insn.id == capstone.x86.X86_INS_IRETD or
                insn.id == capstone.x86.X86_INS_IRETQ)
    
    def is_sysexit_sysret_insn(self, insn:capstone.CsInsn) -> bool:
        return (insn.id == capstone.x86.X86_INS_SYSEXIT or
                insn.id == capstone.x86.X86_INS_SYSRET)
    
    @property
    def page_size(self) -> int:
        return 4096
    
    def parse_interrupt_table(self, proj:angr.Project) -> Dict[int, int]:
        idt_handlers = {}

        idt_table_symbol = proj.loader.find_symbol('idt_table')
        # Assuming all entries are present
        num_entries = 256
        entry_size = 8 if proj.arch.bits == 32 else 16

        if idt_table_symbol is None:
            raise ValueError("idt_table symbol not found")

        # Get the IDT base address
        idt_size = num_entries * entry_size
        assert isinstance(proj.loader.memory, angr.cle.Clemory)
        idt_data = proj.loader.memory.load(idt_table_symbol.rebased_addr, idt_size)

        for i in range(num_entries):
            entry_data = idt_data[i * entry_size : (i + 1) * entry_size]

            if proj.arch.bits == 32:
                # 32-bit IDT entry format: https://wiki.osdev.org/Interrupt_Descriptor_Table#Structure_IA-32
                offset_low, selector, _zero, access, offset_high = struct.unpack('<HHBHB', entry_data)
                handler_addr = (offset_high << 16) | offset_low
            else:
                # 64-bit IDT entry format: https://wiki.osdev.org/Interrupt_Descriptor_Table#Structure_AMD64
                offset_low, selector, ist, access, offset_middle, offset_high = struct.unpack('<HHBBHI', entry_data[0:12])
                handler_addr = (offset_high << 32) | (offset_middle << 16) | offset_low

            # Check if the entry is present (access & 0x80)
            if access & 0x80:
                idt_handlers[i] = handler_addr

        return idt_handlers

    def init_symbols(self, proj:angr.Project) -> None:
        # get the symbol for __x86_return_thunk
        try:
            return_thunk_sym = proj.loader.find_symbol('__x86_return_thunk')
        except KeyError:
            return_thunk_sym = None

        self.return_thunk_addr = return_thunk_sym and return_thunk_sym.rebased_addr

    def is_exception_vector(self, vector:int) -> bool:
        return vector < 32
    
    @property
    def irq_exit_sym_names(self) -> Set[str]:
        return self.__irq_exit_sym_names
    
    @property
    def address_width(self) -> int:
        return 64

arch = ArchX86()
