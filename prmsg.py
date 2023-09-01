# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import sys
import logging
import tqdm
import colors
from time import time
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, TextIO, Sized, Iterable, Union

level_to_logging = {
    #           logging-level,  color,      flush log,  stderr,
    'OP':       (logging.info,  None,       False,      True),
    'INFO':     (logging.info,  'green',    False,      True),
    'FATAL':    (logging.fatal, 'red',      True,       True),
    'ERROR':    (logging.error, 'red',      True,       True),
    'TITLE':    (None,          'blue',     False,      True),
    'DATA':     (None,          None,       False,      False),
    'WARN':     (logging.warning,'yellow',  False,      True),
    'DEBUG':    (logging.warning,'yellow',  False,      True),
}

startup_time = time()

def uptime() -> float:
    return time() - startup_time

output_file:TextIO = sys.stdout
quiet:bool = False
debug_mode:bool = False

def change_output(f_name:str):
    global output_file

    try:
        output_file = open(f_name, 'tw+')
    except Exception as exc:
        raise ValueError(f'error opening output file {f_name}: {str(exc)}')

def pr_msg(msg: str, level:str='INFO', new_line_before:bool=False, new_line_after:bool=False):
    global output_file

    l = level_to_logging[level]
    if l[0] is not None:
        l[0](msg)
        if l[2]:
            logging.getLogger().handlers[0].flush()
    
    o_file = sys.stderr if l[3] else output_file
    std_outputs = o_file in {sys.stderr, sys.stdout}

    if quiet:
        return

    if level == 'DEBUG' and not debug_mode:
        return

    if new_line_before or (Pbar.in_pbar != 0 and std_outputs):
        msg = '\n' + msg
    if new_line_after or (Pbar.in_pbar != 0 and std_outputs):
        msg += '\n'
    if std_outputs and l[1] is not None:
        msg = colors.color(msg, fg=l[1])
    print(msg, file=o_file)

class Pbar(tqdm.tqdm):
    in_pbar = 0

    def __init__(self, message:str, items:Optional[Union[Sized, Iterable]]=None, 
                total:Optional[int]=None, unit:str='it', ignore_zero:bool=True,
                disable:bool=False):
        assert total is not None or isinstance(items, Sized)

        if total is None and isinstance(items, Sized):
            total = len(items)
    
        if quiet or (ignore_zero and total == 0):
            disable = True

        logging.info(message)
        super().__init__(iterable=items, total=total, unit=unit, colour="green",
                        bar_format='{desc:<30.30}{percentage:3.0f}%|{bar:20}{r_bar}',
                        disable=disable)
        super().set_description(message)
        if not disable:
            Pbar.in_pbar += 1
        self.pbar_disabled = disable

    def update_to(self, n:int):
        super().update(n - self.n)

    def __disable(self):
        if not self.pbar_disabled:
            Pbar.in_pbar -= 1
        self.pbar_disabled = True

    def __del__(self):
        self.__disable()
        self.update(self.total - self.n)
        super().__del__()
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__disable()
        if exc_type == None:
            self.update_to(self.total)
        super().__exit__(exc_type, exc_value, traceback)

    def close(self):
        self.__disable()
        super().close()

warned_once:Set[str] = set()

def warn_once(msg: str):
    if msg not in warned_once:
        return
    logging.warning(msg)
    warned_once.add(msg)