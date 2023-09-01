# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import re
import logging
import subprocess
from collections import defaultdict
from typing import List, Dict, Optional, Tuple

class Addr2Line:
    addr2line_loc_re = re.compile(r'(?P<file>[^\:]+):(?P<line>\d+)\s*(?P<disc>.*)')
    llvm_symbolizer_loc_re = re.compile(r'(?P<file>[^\:]+):(?P<line>\d+):(?P<col>\d+)\s*(?P<disc>.*)')

    __instance: Optional['Addr2Line'] = None
    __llvm_symbolizer = 'llvm-symbolizer'
    __addr2line = 'addr2line'

    @property
    def llvm_symbolizer(self) -> str:
        return self.__llvm_symbolizer

    @llvm_symbolizer.setter
    def llvm_symbolizer(self, llvm_symbolizer:str):
        self.__llvm_symbolizer = llvm_symbolizer

    @property
    def addr2line(self) -> str:
        return self.__addr2line

    @addr2line.setter
    def addr2line(self, addr2line:str):
        self.__addr2line = addr2line

    @staticmethod
    def get_instance():
        """ Static access method. """
        if Addr2Line.__instance == None:
            Addr2Line()
        return Addr2Line.__instance

    def __init__(self):
        """ Virtually private constructor. """
        if Addr2Line.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            Addr2Line.__instance = self

    def run(self, obj_addrs:List[Tuple[str, int]]) -> Dict[Tuple[str, int], List[Dict]]:
        # Split the addresses according to the file (the first in the tuple)
        addr_dict:defaultdict[str, List[int]] = defaultdict(list)

        for obj, addr in obj_addrs:
            addr_dict[obj].append(addr)

        result:Dict[Tuple[str, int], List[Dict]] = {}
        for obj, addrs in addr_dict.items():
            addr_args = [hex(a) for a in addrs]

            # Try llvm-symbolizer first since it gives the column
            output = None
            args = [self.llvm_symbolizer, f'--obj={str(obj)}', "--basenames",
                    '--relativenames', '--print-address', *addr_args]
            logging.info("running: {0}".format(' '.join(args)))

            try:
                output = subprocess.check_output(
                    args, stderr=subprocess.STDOUT, timeout=20,
                    universal_newlines=True)
            except:
                pass

            line_re = self.llvm_symbolizer_loc_re

            if output is None:
                args = [self.addr2line, '-a', '-f', '-i', '-e', str(obj)]
                args.extend(addr_args)
                logging.info("running: {0}".format(' '.join(args)))
                try:
                    output = subprocess.check_output(
                        args, stderr=subprocess.STDOUT, timeout=20,
                        universal_newlines=True)
                except:
                    raise SystemError(f'Failed to run {self.addr2line} and {self.llvm_symbolizer} on {obj}')

                line_re = self.addr2line_loc_re

            func = None

            for l in output.splitlines():
                if l == "":
                    continue
                elif l.startswith("0x"):
                    addr = int(l, 16)
                    func = None
                    skip = (obj, addr) in result
                    if not skip:
                        result[(obj, addr)] = list()
                elif func is None:
                    func = l
                elif not skip:
                    m = line_re.match(l)
                    d = m.groupdict()
                    col = int(d['col']) if 'col' in d else None
                    loc = {'func':func, 'file':d['file'], 'line':int(d['line']), 'col':col}
                    result[obj, addr].append(loc)
                    func = None
            
        return result