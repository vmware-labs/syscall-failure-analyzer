# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import re
import logging
from typing import List, Dict, Optional, Any
from elftools.elf.elffile import ELFFile

class Kcore:
    iomem_regex = re.compile(r'\s*(?P<start>[0-9a-f]+)\-(?P<end>[0-9a-f]+)\s+:\s+(?P<type>[^\n]+)')
    path = "/proc/kcore"

    # Singleton instance variable
    _instance:Optional['Kcore'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'f_kcore'):
            self.open()

    def __del__(self):
        if hasattr(self, 'f_kcore'):
            self.f_kcore.close()

    def open_iomem(self):
        ranges = list()
        with open("/proc/iomem") as f:
            for l in f:
                m = self.iomem_regex.match(l)
                if m is None:
                    continue
                d = m.groupdict()
                if d['type'] != 'System RAM':
                    continue
                ranges.append((int(d['start'], 16), int(d['end'], 16)))

    def open(self) -> bool:
        try:
            self.f_kcore = open(self.path, mode='rb')
        except PermissionError:
            raise Exception("no access to kcore")

        elf = ELFFile(self.f_kcore)

        self.phdr = list()
        for seg in iter(elf.iter_segments('PT_LOAD')):
            self.phdr.append(seg.header)

        self.modules = self.parse_proc_modules()

        return True
    
    def get_offset(self, addr: int) -> int:
        for s in self.phdr:
            if s.p_vaddr <= addr and addr < s.p_vaddr + s.p_filesz:
                break

        if s is None:
            raise ValueError("Address not found")

        offset = addr - s.p_vaddr
        return s.p_offset + offset

    def read(self, addr:int, sz:int) -> bytes:
        found = None
        for s in self.phdr:
            if s.p_vaddr <= addr and addr < s.p_vaddr + s.p_filesz:
                found = s
                break

        if found is None:
            raise ValueError("Address not found")

        offset = addr - found.p_vaddr
        self.f_kcore.seek(s.p_offset + offset)
        try:
            b = self.f_kcore.read(sz)
        except:
            logging.info(f'failed to read kcore at {hex(addr)}')
            b = bytes()
        return b
    
    def parse_proc_modules(self) -> List[Dict[str, Any]]:
        modules = []

        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split(' ')
                module_name = parts[0]
                module_size = int(parts[1])
                module_ref_count = None if parts[2] == '-' else int(parts[2])
                module_dependencies = [dep for dep in parts[4].split(',') if dep != '-']
                module_state = parts[4]
                module_address = int(parts[5], 16)

                module_info = {
                    'name': module_name,
                    'size': module_size,
                    'ref_count': module_ref_count,
                    'dependencies': module_dependencies,
                    'state': module_state,
                    'address': module_address
                }
                modules.append(module_info)

        return modules