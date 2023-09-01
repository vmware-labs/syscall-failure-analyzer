# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, Callable
import logging
import pathlib
import subprocess
import io
import abc
import struct
import os
from enum import Enum
from prmsg import pr_msg
from collections import defaultdict
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

import cle.backends
import angr
from arch import arch

NT_GNU_BUILD_ID = 3

def get_vmlinux(user_option:Optional[List[BinaryIO]]) -> List[BinaryIO]:
    if user_option is None:
        user_option = []

    # Check if any of the filenames includes 'vmlinux'
    if any('vmlinux' in pathlib.Path(f.name).stem for f in user_option):
        return user_option
    
    vmlinux_search = [
        f'/usr/lib/debug/boot/vmlinux-{os.uname().release}',
        'vmlinux'
    ]
    for vmlinux in vmlinux_search:
        try:
            f = open(vmlinux, 'rb')
            pr_msg(f'Using vmlinux file {vmlinux}', level='INFO')
            user_option.append(f)
            return user_option
        except FileNotFoundError:
            pass
        except PermissionError:
            pr_msg(f'Could not open vmlinux file {vmlinux}', level='ERROR')

    pr_msg('Could not find vmlinux file, trying to continue without one', level='ERROR')
    pr_msg('''Consider installing symbols using:
                sudo apt install linux-image-$(uname -r)-dbgsym [deb/ubuntu]
                sudo dnf debuginfo-install kernel [fedora]
                sudo pacman -S linux-headers [arch]
                sudo emerge -av sys-kernel/linux-headers [gentoo]
            ''', level='WARN')
    return user_option

def find_module_dbg(module_name:str):
    pathes = [f'/usr/lib/debug/lib/modules/{os.uname().release}']
    for path in pathes:
        if not os.path.exists(path) or not os.path.isdir(path):
            continue
        for root, dirs, files in os.walk(path):
            for file in files:
                if file == f'{module_name}.ko' or file == f'{module_name}.ko.debug':
                    return os.path.join(root, file)
    return None

class Kallsyms:
    def __init__(self, objs:List[io.BufferedReader]):
        parsed_modules = self.parse_proc_modules()
        self.__find_modules(parsed_modules)

        self.keep_sym_types: Set[str] = {'t', 'T', 'w', 'W', 'r', 'R'}
        self.type_map:Dict[str, angr.cle.backends.SymbolType] = {
                    'a':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'A':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'd':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'D':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'b':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'B':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'r':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'R':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'v':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'V':angr.cle.backends.SymbolType.TYPE_OTHER,
                    't':angr.cle.backends.SymbolType.TYPE_FUNCTION,
                    'T':angr.cle.backends.SymbolType.TYPE_FUNCTION,
                    'w':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'W':angr.cle.backends.SymbolType.TYPE_OTHER,
        }

        all_syms = self.__read_symbols()
        all_segments = self.__analyze_sections(all_syms)
        self.exes = dict()

        obj_basenames = {self.__get_basename(pathlib.Path(f.name).stem):f for f in objs}

        def get_obj_base_sz(obj_name:str, syms) -> Tuple[int, int]:
            if obj_name == 'vmlinux':
                min_addr = next(s[1] for s in syms if s[0] == '_stext')
                max_addr = next(s[1] for s in syms if s[0] == '_end')
                sz = max_addr - min_addr
            elif obj_name in parsed_modules:
                min_addr = parsed_modules[obj_name]['address']
                sz = int(parsed_modules[obj_name]['size'])
            else:
                min_addr = self.__get_min_addr(syms)
                max_addr = self.__get_max_addr(syms)
                sz = max_addr - min_addr

            return min_addr, sz


        for obj_name, syms in all_syms.items():
            mapped_addr, sz = get_obj_base_sz(obj_name, syms)

            path = None
            if obj_name in obj_basenames:
                path = obj_basenames[obj_name].name
            elif obj_name in parsed_modules:
                path = parsed_modules[obj_name].get('path')

            if path is not None:
                with open(path, 'rb') as f:
                    if not self.check_build_id(f):
                        pr_msg(f'Build ID mismatch for {obj_name}', level='WARN')
                        path = None
 
            self.exes[obj_name] = {
                'mapped_addr': mapped_addr,
                'base_addr': arch.default_text_base if obj_name == 'vmlinux' else 0,
                'size': sz,
                'symbols': [],
                'path': path,
                'segments': all_segments[obj_name],
            }
            
            if path is None:
                self.exes[obj_name]['symbols'] = self.__relative_symbol_tuples(syms, mapped_addr, sz)
                continue
           
            try:
                with open(path, 'rb') as f:
                    base_syms = self.__read_sizes(f)
            except FileNotFoundError as e:
                pr_msg(f'Could not find file {f}: {e}', level='WARN')
                continue

            base_addr, _ = get_obj_base_sz(obj_name, base_syms)
            rebased_syms = self.__relative_symbol_tuples(base_syms, base_addr, sz)
           
            # Complicated since mypy doesn't like direct assignment
            self.exes[obj_name].update({
                'base_addr': base_addr,
                'symbols': rebased_syms,
            })

    def __find_modules(self, parsed_modules):
        pathes = [f'/usr/lib/debug/lib/modules/{os.uname().release}']

        for path in pathes:
            if not os.path.exists(path) or not os.path.isdir(path):
                continue

            for root, dirs, files in os.walk(path):
                for file in files:
                    if not file.endswith('.ko.debug') and not file.endswith('.ko'):
                        continue

                    # In kallsyms modules show with underscores instead of dashes
                    basename = pathlib.Path(file).stem.split('.')[0]
                    basename_underscored = basename.replace('-', '_')

                    for obj_name in [basename, basename_underscored]:
                        if obj_name in parsed_modules:
                            parsed_modules[obj_name]['path'] = os.path.join(root, file)
            break

    def __relative_symbol_tuples(self, syms:List[Tuple[str, int, str, Optional[int]]], min_addr:int, sz:int) -> List[Tuple[str, int, str, Optional[int]]]:
            max_addr = min_addr + sz

            return [(s[0], s[1] - min_addr, s[2], s[3]) for s in syms if s[1] >= min_addr and s[1] < max_addr]

    def __get_min_addr(self, syms:List[Tuple[str, int, str, Optional[int]]]) -> int:
        return min([s[1] for s in syms if s[2] in {'t', 'T', 'r', 'R'}])

    def __get_max_addr(self, syms:List[Tuple[str, int, str, Optional[int]]]) -> int:
        return max([s[1] + s[3] for s in syms if s[2] in {'t', 'T', 'r', 'R'} and s[3] is not None])


    def __read_symbols(self) -> Dict[str, List[Tuple[str, int, str, Optional[int]]]]:
        builtin_index:defaultdict[str, int] = defaultdict(int)
        global arch

        f = open("/proc/kallsyms", "rb")
        logging.info("reading symbols")
        f.seek(0)

        data = f.read().decode("ascii")

        raw = []
        for l in data.splitlines():
            name = l.split()[2]
            addr = int(l.split()[0], 16)
            sym_type = l.split()[1]
            module_name = 'vmlinux' if len(l.split()) < 4 else l.split()[3][1:-1]

            # Builtin sections can overlap each other, which angr doesn't like. So
            # we are not going to merge them. And instead we are creating each one a
            # unique name with a different suffix.
            if module_name.startswith('__builtin') or module_name in {'bpf'}:
                suffix = builtin_index[module_name]
                builtin_index[module_name] += 1
                module_name = f'{module_name}:{suffix}'

            raw.append((name, addr, sym_type, module_name))

        list.sort(raw, key=lambda x:x[1])
        if len(raw) == 0:
            pr_msg("cannot read symbol addresses from kallsyms", level="ERROR")
            raise Exception()

        syms = defaultdict(list)

        # Guess the sizes
        prev = raw[0]
        for sa in raw[1:]:
            syms[prev[3]].append((prev[0], prev[1], prev[2], sa[1] - prev[1])) 
            prev = sa

        remaining_in_page = arch.page_size - prev[1] % arch.page_size
        syms[prev[3]].append((prev[0], prev[1], prev[2], remaining_in_page))
        return syms # type: ignore
    
    def __analyze_sections(self, syms:Dict[str, List[Tuple[str, int, str, Optional[int]]]]) -> Dict[str, List[Tuple[int, int]]]:
        segments_dict = dict()
        vmlinux = syms['vmlinux']

        for k, v in syms.items():
            sections:List[Tuple[int, int]] = []
            cur_section_start = None
            cur_section_end = None

            for sa in v:
                if sa[3] is None:
                    continue
                if sa[2] in self.keep_sym_types:
                    if cur_section_start is None:
                        cur_section_start = sa[1]
                    cur_section_end = sa[1] + sa[3]
                elif sa[2] not in self.keep_sym_types and cur_section_start is not None:
                    cur_section_end = sa[1]
                    if cur_section_start != cur_section_end:
                        sections.append((cur_section_start, sa[1]))
                    cur_section_start = None

            if cur_section_start is not None:
                assert cur_section_end is not None
                sections.append((cur_section_start, cur_section_end))

            segments_dict[k] = sections

        include_ranges_syms = [
            ('__start_rodata', '__end_rodata'),
            ('_stext', '_etext'),
        ]
        # find the symbols from include_ranges_syms in vmlinux
        include_ranges = []
        for start, end in include_ranges_syms:
            start_addr = next(s[1] for s in vmlinux if s[0] == start)
            end_addr = next(s[1] for s in vmlinux if s[0] == end)
            include_ranges.append((start_addr, end_addr))

        # TODO: Move to arch
        start_addr = next(s[1] for s in vmlinux if s[0] == 'idt_table')
        end_addr =  start_addr + 4096
        include_ranges.append((start_addr, end_addr))

        combined_ranges = segments_dict['vmlinux'] + include_ranges
        combined_ranges.sort(key=lambda x: x[0])

        # Initialize the merged ranges list with the first range
        merged_ranges = [combined_ranges[0]]

        for current_start, current_end in combined_ranges[1:]:
            last_range_start, last_range_end = merged_ranges[-1]

            # Check if the current range overlaps or is adjacent to the last range in the merged list
            if current_start <= last_range_end + 1:
                # Update the end value of the last range to the maximum of the current and last end values
                merged_ranges[-1] = (last_range_start, max(current_end, last_range_end))
            else:
                # If the current range doesn't overlap or is not adjacent, append it to the merged list
                merged_ranges.append((current_start, current_end))

        segments_dict['vmlinux'] = merged_ranges

        return segments_dict

    @staticmethod
    def __get_basename(filename: str) -> str:
        if filename.startswith('vmlinux'):
            return 'vmlinux'
        
        stem = filename.split('.')[0]
        return stem.replace('-', '_')

    @staticmethod
    def extract_build_id(data) -> Optional[str]:
        build_id = None
        offset = 0
        while offset < len(data):
            namesz, descsz, note_type = struct.unpack_from('III', data, offset)
            offset += 12

            name_start = offset
            name_end = name_start + namesz

            desc_start = (name_end + 3) & ~3
            desc_end = desc_start + descsz

            # Get it from the last note if there are multiple ones
            if note_type == NT_GNU_BUILD_ID:
                build_id = data[desc_start:desc_end]

            offset = (desc_end + 3) & ~3
        
        if build_id is None:
            return None
        
        build_id_hex = ''.join([format(byte, '02x') for byte in build_id])
        return build_id_hex

    @staticmethod
    def get_module_build_id(module_name) -> Optional[str]:
        build_id_path = pathlib.Path(f"/sys/module/{module_name}/notes/.note.gnu.build-id")
        
        if not build_id_path.exists():
            raise Exception(f"{build_id_path} not found. Ensure the module is loaded and you have the required permissions.")

        data = build_id_path.read_bytes()
        return Kallsyms.extract_build_id(data)

    @staticmethod
    def get_build_id_from_vmlinux(vmlinux_file:io.BufferedReader) -> Optional[str]:
        r = None
        #with open(vmlinux_file, 'rb') as f:
        elf = ELFFile(vmlinux_file)
        for section in elf.iter_sections():
            if isinstance(section, NoteSection):
                for note in section.iter_notes():
                    if note.n_type == 'NT_GNU_BUILD_ID':
                        r = note.n_desc
        return r

    @staticmethod
    def get_build_id_from_kernel_notes(kernel_notes_file:pathlib.Path):
        data = kernel_notes_file.read_bytes()
        return Kallsyms.extract_build_id(data)

    @staticmethod
    def check_build_id(obj_file:io.BufferedReader) -> bool:
        file_build_id = Kallsyms.get_build_id_from_vmlinux(obj_file)

        path = pathlib.Path(obj_file.name)
        basename = Kallsyms.__get_basename(path.name)

        if basename == 'vmlinux':
            live_build_id = Kallsyms.get_build_id_from_kernel_notes(pathlib.Path("/sys/kernel/notes"))
        else:
            live_build_id = Kallsyms.get_module_build_id(basename)
        
        if file_build_id is None:
            logging.info(f"no build ID found in {obj_file}")
            return False
        
        if live_build_id is None:
            logging.info(f"no build ID found in kernel")
            return False
        
        if file_build_id != live_build_id:
            logging.info(f"build ID mismatch: {file_build_id} != {live_build_id}")
            return False
        
        return True


    def __read_sizes(self, file:io.BufferedReader) -> List[Tuple[str, int, str, Optional[int]]]:
        filename = pathlib.Path(file.name)
        logging.info(f"reading symbol sizes: {filename}")

        # Reading the ELF using elftools is incredibly slow. Use nm instead.
        args = ['nm', '-n', '--print-size', str(filename)]
        logging.debug("running: {0}".format(' '.join(args)))
        try:
            output = subprocess.check_output(
                args, stderr=subprocess.STDOUT, timeout=20,
                universal_newlines=True)
        except subprocess.CalledProcessError as e:
            pr_msg(f"failed reading symbol file: {e}", level="ERROR")
            raise e

        lns = [[l[:16]] + l[17:].split() for l in output.splitlines()]

        syms = [(l[3 if len(l) == 4 else 2],                # name
            int(l[0], 16),                                  # addr
            l[2 if len(l) == 4 else 1],                     # type
            (int(l[1], 16)) if len(l) == 4 else None)       # size
            for l in lns if len(l) <= 4 and l[0] != ' ' * 16]

        return syms

    def parse_proc_modules(self) -> Dict[str, Dict[str, Any]]:
        modules = dict()

        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split()
                module_name = parts[0]
                module_size = int(parts[1])
                module_ref_count = None if parts[2] == '-' else int(parts[2])
                module_dependencies = [dep for dep in parts[4].split(',') if dep != '-']
                module_state = parts[4]
                module_address = int(parts[5], 16)

                module_info = {
                    'size': module_size,
                    'ref_count': module_ref_count,
                    'dependencies': module_dependencies,
                    'state': module_state,
                    'address': module_address
                }
                modules[module_name] = module_info

        return modules

    def get_symbols(self, backend:cle.Backend, name:str) -> List[cle.Symbol]:
        syms = self.exes[name]['symbols']
        assert isinstance(syms, list)

        syms = [cle.Symbol(owner = backend, name = s[0],
                relative_addr = s[1],
                sym_type = self.type_map[s[2]],
                size = s[3]) for s in syms]

        return syms