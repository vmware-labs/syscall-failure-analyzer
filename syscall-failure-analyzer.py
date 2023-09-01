#!/usr/bin/python3
# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import glob
import logging
import os
import pickle
import sys
import io
import lz4.frame
from typing import Optional, Set, List, BinaryIO

from angrmgr import Angr
from addr2line import Addr2Line
from claripy.backends.backend_smtlib_solvers import *
from intelptrecorder import IntelPTRecorder
from intelptreporter import IntelPTReporter
from kallsyms import Kallsyms, get_vmlinux
from kprobesrecorder import KProbesRecorder
from kprobesreporter import KprobesReporter
from reporter import Reporter
from prmsg import pr_msg, quiet, warn_once, change_output
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from syscall import ErrorcodeInfo, SyscallInfo
from kcore import Kcore
from ftrace import Ftrace

DEFAULT_DATA_FILENAME = 'deeperr.data'


def get_occurrences(s:str) -> Optional[Set[int]]:
    if s is None:
        return None
    if s.isnumeric():
        return {int(s)}
    try:
        r = {int(v.strip()) for v in s.split(',')}
    except:
        pr_msg('Could not parse occurances list, skipping input', level='ERROR')
        r = None

    return r

def report(inputs: str,
           src_path: Optional[str],
           output: Optional[str],
           print_stats: bool,
           objs: List[io.BufferedReader],
           syscall_filter: Optional[int],
           errcode_filter: Optional[int],
           occurances_filter: Optional[Set[int]],
           **kwargs):
    if output is not None:
        try:
            change_output(output)
        except Exception as e:
            pr_msg(f'{e}', level='FATAL')
            return

    res_files = glob.glob(inputs)
    if len(res_files) == 0:
        pr_msg('found no result files', level="ERROR")
        return

    for f_name in res_files:
        try:
            with lz4.frame.open(f_name, 'rb') as failure_file:
                # Load the data from the file
                data = pickle.load(failure_file)
        except FileNotFoundError:
            pr_msg(f'error reading result file {f_name}: file not found', level='ERROR')
            continue
        except EOFError:
            pr_msg(f'error reading result file {f_name}: file is empty', level='ERROR')
            continue
        except lz4.frame.LZ4FrameError:
            pr_msg(f'error reading result file {f_name}: file is corrupted', level='ERROR')
            continue
        
        kallsyms = data.get('kallsyms', Kallsyms(objs))
        saved_segs = data.get('kcore')
        kcore = Kcore() if saved_segs is None else None

        if saved_segs is None:
            pr_msg(f'kcore was not saved, reading from /proc/kcore', level='INFO')

        # We need to init ftrace before angr to clear all probe points that
        # might have been left. Otherwise, disassembly will fail.
        ftrace = Ftrace()
        ftrace.kprobe_event_disable_all()

        angr_mgr = Angr(kallsyms, 
                        kcore = kcore,
                        saved_segs = saved_segs)

        reporter_cls = IntelPTReporter if data['type'] == 'intel-pt' else KprobesReporter
        report_kwargs = {
            'objs': objs,
            'errcode_filter': errcode_filter,
            'syscall_filter': syscall_filter,
            'print_stats': print_stats,
            # Filtering based on occurances is done during reporting only for Intel PT,
            # since we cannot reliably filter it out during recording
            'occurances_filter': occurances_filter,
            'angr_mgr': angr_mgr,
            'traces': data['traces'],
            'failures': data['failures'],
            'src_path': src_path,
        }

        reporter:Reporter = reporter_cls(**report_kwargs)
        reporter.report()


def valid_path(path):
    if os.path.exists(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"Path '{path}' does not exist.")

def main():
    global quiet, debug

    def arg_error(parser: argparse.ArgumentParser):
        # add suffix to the usage string
        parser.print_help()
        exit()

    parser = argparse.ArgumentParser("deeperr", epilog="application")
    parser.add_argument('--verbose', '-v', action='store_true', dest='verbose', help='prints verbose analysis info')
    parser.add_argument('--vmlinux', '-l', action='store', dest='objs', help='location of vmlinux file or other modules', type=argparse.FileType('rb'), nargs='+', default=[])
    parser.add_argument('--perf', '-f', default='perf', metavar=argparse.FileType('x'), help='location of perf')
    parser.add_argument('--debug', '-d', action='store_true', dest='debug', help='debug mode verbosity')
    parser.add_argument('--llvm-symbolizer', '-y', action='store', dest='llvm_symbolizer', default='llvm-symbolizer', help='path to llvm-symbolizer')
    parser.add_argument('--snapshot-size', '-z', action='store', dest='snapshot_size', type=int, default=262144, help='perf snapshot size')
    parser.add_argument('--tmp', '-t', action='store', dest='tmp_path', default='/tmp', type=valid_path, help='tmp path')
    parser.add_argument('--syscall', '-s', action='store', dest='syscall', help='failing syscall number to track')
    parser.add_argument('--quiet', '-q', action='store_true', dest='quiet', help='quiet mode')
    parser.add_argument('--errcode', '-r', action='store', dest='errcode', help='error number')
    parser.add_argument('--output', '-o', action='store', dest='output', help='output file', default=None, metavar='PATH')
    parser.add_argument('--input', '-i', action='store', dest='input', help='input file', default=DEFAULT_DATA_FILENAME, metavar='FILES')
    parser.add_argument('--kprobes', '-k', action='store_true', dest='kprobes', help='use kprobes')
    parser.add_argument('--occurrences', '-n', action='store', dest='occurrences', help='occurrences to record')
    parser.add_argument('--extra-info', '-x', action='store_true', dest='print_stats', help='detailed output with analysis statistics')
    parser.add_argument('--path', '-p', action='store', dest='src_path', default=None, type=valid_path, help='path to source code')
    parser.add_argument('--nokcore', '-w', action='store_true', dest='nokcore', help='do not save kcore')
    parser.add_argument('--early-stop', '-e', action='store_true', dest='early_stop', help='stop execution after first failure')
    parser.add_argument('command', choices=['record', 'report'], help='command to run: record or report')

    parser.usage = parser.format_usage()[7:].rstrip('\n ') + ' -- <command> [args]\n'

    try:
        args, remaining_argv = parser.parse_known_args()
    except:
        # Exit with error
        exit(1)

    if os.geteuid() != 0:
        pr_msg(f'{sys.executable} must be run as root', level='FATAL')
        exit(1)

    if remaining_argv and remaining_argv[0] == '--':
        remaining_argv = remaining_argv[1:]
    
    sys.setrecursionlimit(10 ** 5)

    loglevel = 'ERROR'
    if args.debug:
        loglevel = 'DEBUG'
    elif args.verbose:
        loglevel = 'INFO'

    quiet = args.quiet
    debug = args.debug

    logging.basicConfig(filename='deeperr.log', level=loglevel, force=True)
    logging.getLogger().setLevel(loglevel)
    for l in ['angr', 'cle', 'pyvex', 'claripy']:
        logging.getLogger(l).setLevel('ERROR')

    objs = get_vmlinux(args.objs)

    syscall_filter = None
    if args.syscall is not None:
        try:
            syscall_filter = SyscallInfo.get_syscall_nr(args.syscall)
        except ValueError as e:
            pr_msg(e, level="ERROR")
            pr_msg('recording all syscall', level="WARN")

    syscall_filter = SyscallInfo.get_syscall_nr(args.syscall)
    errcode_filter = ErrorcodeInfo.get_errno(args.errcode)
    occurrences_filter = get_occurrences(args.occurrences)

    a2l = Addr2Line.get_instance()
    a2l.llvm_symbolizer = args.llvm_symbolizer

    if args.command == 'record' and len(remaining_argv) < 1:
        arg_error(parser)

    if args.command == 'record':
        kprobes = args.kprobes
        kcore = Kcore()

        if kprobes and not IntelPTRecorder.cpu_supports_pt():
            pr_msg("CPU does not support Intel PT", level="ERROR")

        recorder_cls = KProbesRecorder if kprobes else IntelPTRecorder
        a = recorder_cls(
            perf=args.perf,
            objs=objs,
            snapshot_size=args.snapshot_size,
            errcode_filter=errcode_filter,
            syscall_filter=syscall_filter,
            occurrences_filter=occurrences_filter,
            output=args.output or 'deeperr.data',
            tmp_path=args.tmp_path,
            debug=args.debug,
            save_kcore=not args.nokcore,
            early_stop=args.early_stop,
        )
        try:
            a.record(args=remaining_argv)
        except OSError as e:
            pr_msg(f'error recording: {e}', level='FATAL')
    else:
        report(inputs=args.input,
               output=args.output,
               print_stats=args.print_stats,
               objs=objs,
               errcode_filter=errcode_filter,
               syscall_filter=syscall_filter,
               occurances_filter=occurrences_filter,
               src_path=args.src_path)

if __name__ == "__main__":
    main()