# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import pathlib
import errno
import subprocess
import signal
import os
import re
import time
import ctypes
import shutil
import psutil
from typing import Optional, Set, List
from recorder import Recorder
from prmsg import pr_msg
from syscall import ret_to_err, SyscallInfo, ErrorcodeInfo
from ptrace.syscall.ptrace_syscall import SYSCALL_NAMES
from bcc import BPF, DEBUG_SOURCE
from kcore import Kcore

class IntelPTRecorder(Recorder):
    def __init__(
        self,
        tmp_path: str,
        **kwargs
    ):
        occurrences_filter = kwargs.get('occurrences_filter')
        if occurrences_filter is None or len(occurrences_filter) > 1:
            pr_msg('Using Intel PT only one failure can be recorded', level="WARN")
            kwargs['occurrences_filter'] = {1}

        kwargs['kcore'] = Kcore() if kwargs.get('save_kcore') else None

        super().__init__(**kwargs)
        self.record_proc:Optional[subprocess.Popen[bytes]] = None
        self.record_proc_terminated = False
        self.tmp_path = pathlib.Path(tmp_path)
        self.sorted_occurrence_filter = sorted(self.occurrences_filter) if self.occurrences_filter else None

        error_pattern = r'^ERROR: (?P<error>.*)$'
        self.error_regex = re.compile(error_pattern)

        dump_pattern = r'\[ perf record: Dump (.*?) \]'
        self.dump_regex = re.compile(dump_pattern)


    def init_tmp_path(self):
        if not self.tmp_path.exists() or not self.tmp_path.is_dir():
            pr_msg(f'error: tmp path [{self.tmp_path}] is not a valid tmp directory', level="FATAL")
            return False

        self.my_tmp_path = self.tmp_path.joinpath(pathlib.Path("errexp"))
        if not self.my_tmp_path.exists():
            try:
                self.my_tmp_path.mkdir()
            except:
                pr_msg(f"error creating tmp path [{self.my_tmp_path}]", level="FATAL")
                return False
        
        return True
    
    def handle_event(self, cpu, data, size):
        event = self.bpf['syscall_events'].event(data)
        pid = event.pid
        syscall = event.syscall_nr
        err = ret_to_err(event.syscall_ret)

        e = {'err': err, 'syscall_nr': syscall, 'pid': pid, 'ts': event.ts/1e9}

        try:
            self.record_proc.send_signal(signal.SIGUSR2)
        except ProcessLookupError:
            pr_msg("perf process already terminated", level='WARN')
            self.dump_filenames = []
            return

        # Snapshots do not work well with Intel PT, and since the parent might already have
        # many children, it is problematic to attach perf only to these processes again.        
        # Wake the thread that reported the error, since the eBPF paused it to allow
        # tracing to be more successful, but let's give one second before we do so.
        if not self.early_stop:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
 
        # For the same reason we only track one failure
        if len(self.failures) == 0:
            self.failures.append(e)

    def run_perf_record(self, pid: int):
        e_entry_class, e_entry_subclass, entry_filter = self.get_filter_string(exit=False)
        e_exit_class, e_exit_subclass, exit_filter = self.get_filter_string(exit=True)

        # We need to save kcore since without it, retpolines are not resolved
        record_args_raw = [self.perf, "record",
                    '-e', 'intel_pt/noretcomp=1/k',
#                    '-e', f'{e_entry_class}:{e_entry_subclass}',
#                    entry_filter and f'--filter={entry_filter}',
#                    '-e', f'{e_exit_class}:{e_exit_subclass}',
#                    exit_filter and f'--filter={exit_filter}',
                    '--kcore',
                    '--timestamp',
                    '-p', f'{pid}',
                    '--switch-output',
                    f'--snapshot=e{self.snapshot_size}',
                    f'-m,{(self.snapshot_size >> 12)}']

        record_args_raw.append(f'-o{self.my_tmp_path.joinpath("perf.data")}')
        
        record_args = [arg for arg in record_args_raw if arg is not None]

        pr_msg(f"running: {' '.join(record_args)}", level="INFO")

        record_proc = subprocess.Popen(record_args, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)

        if record_proc is None:
            raise SystemError("error starting perf record")
        
        # Save the process for handle_event to see it

        time.sleep(2)

        # Check that perf is running
        if record_proc.poll() is not None:
            record_proc.wait()
            assert record_proc.stdout is not None
            perf_output = record_proc.stdout.read()
            perf_output_str = perf_output.decode('utf-8')
            pr_msg(f"perf failed: {perf_output_str}", level="FATAL")
            pr_msg(f"hint: check that perf that is compatiable with the current kernel was provided", level="WARN")
            raise SystemError("error running perf record")
        
        self.record_proc = record_proc

    def run_perf_script(self, file: str) -> str:
        args = [self.perf, "script", "--itrace=b", "-i", file]
        pr_msg(f"running: {' '.join(args)}", level='INFO')

        try:
            output = subprocess.check_output(
                args,
                stderr=subprocess.STDOUT,
                timeout=60,
                universal_newlines=True
            )
        except (subprocess.CalledProcessError, PermissionError, subprocess.TimeoutExpired) as exc:
            raise SystemError(f"error starting perf itrace: {exc}")

        return output

    def cleanup(self):
        if self.my_tmp_path and self.my_tmp_path.exists():
            shutil.rmtree(self.my_tmp_path)
        self.my_tmp_path = None

    def prepare_bpf(self):
        # There is a bug in bcc that causes a warning to be printed to stderr
        syscall_name = SYSCALL_NAMES.get(self.syscall_filter, None)

        b = BPF(src_file="syscall_failure_ebpf.c",
                cflags=["-w", "-Wno-error", "-Wno-warning"],
                debug=DEBUG_SOURCE if self.debug else 0)

        tp = (f"syscalls:sys_exit_{syscall_name}" if False and syscall_name is not None else
               "raw_syscalls:sys_exit")
        
        def create_ulonglong(value):
            return ctypes.c_ulonglong(value) if value is not None else ctypes.c_ulonglong(0xffffffffffffffff)

            # Config keys
        SYSCALL_FILTER_KEY = 1
        ERRCODE_FILTER_KEY = 2
        MONITORED_PID_KEY = 3
        SORTED_OCCURRENCE_FILTER_KEY = 4
        FLAGS_KEY = 5

        # Create a dictionary to store config
        config_map = {
            SYSCALL_FILTER_KEY: self.syscall_filter,
            ERRCODE_FILTER_KEY: -self.errcode_filter if self.errcode_filter is not None else None,
            MONITORED_PID_KEY: self.monitored_pid,
            SORTED_OCCURRENCE_FILTER_KEY: self.sorted_occurrence_filter[0] if self.sorted_occurrence_filter else None,
            FLAGS_KEY: 1 if self.early_stop else 0
        }

        for key, value in config_map.items():
            b["config_map"][ctypes.c_ulonglong(key)] = create_ulonglong(value)

        b.attach_tracepoint(tp=tp, fn_name="trace_syscalls")
        b["syscall_events"].open_perf_buffer(self.handle_event)
        self.bpf = b

    def close_perf(self):
        if self.record_proc is None:
            return

        if self.record_proc.poll():
            try:
                self.record_proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pr_msg("perf process already terminated", level='WARN')
                self.dump_filenames = []
                return

        err = self.record_proc.wait()
        assert self.record_proc.stdout is not None
        perf_output = self.record_proc.stdout.read()
        perf_output_str = perf_output.decode('utf-8')
        pr_msg(f'record proc output: {perf_output_str}', level='DEBUG')
        if err not in {0, None, -errno.ENOENT}:
            pr_msg(f'error closing perf: {err}', level="WARN")

        matches = self.error_regex.findall(perf_output_str, re.MULTILINE)
        if matches:
            pr_msg(matches[0], level='ERROR')
            raise Exception(matches[0])

        matches = self.dump_regex.findall(perf_output_str)
        if not matches:
            pr_msg(f'perf output: {perf_output_str}', level='ERROR')
            raise Exception('failed to find perf dump file')
        
        # Snapshots are broken with Intel-PT. Take only the first one.
        self.dump_filenames = [match for match in matches][:1]
        self.record_proc = None
 
    def record(self, args:'list[str]') -> int:
        if not self.init_tmp_path():
            return 0

        collected = 0

        try:
            self.init_process(args)
        except (FileNotFoundError, PermissionError) as e:
            pr_msg(f"error starting process: {e}", level="FATAL")
            return 0

        self.prepare_bpf()
        self.run_perf_record(self.monitored_pid)

        assert self.record_proc is not None

        self.detach_all_processes() 

        try:
            while not self.early_stop or len(self.failures) == 0:
                self.bpf.perf_buffer_poll(1)
                time.sleep(0.001)
                try:
                    terminated_pid, _ = os.waitpid(self.monitored_pid, os.WNOHANG)
                    if terminated_pid == self.monitored_pid:
                        pr_msg(f'Child process {terminated_pid} terminated', level='INFO')
                        break
                except ChildProcessError:
                    pass
        except KeyboardInterrupt:
            pr_msg("Interrupted - stop recording", level='INFO')

        if psutil.pid_exists(self.monitored_pid):
            try:
                os.kill(self.monitored_pid, signal.SIGINT)
            except ProcessLookupError:
                pr_msg("monitored process already terminated", level='WARN') 

        self.close_perf()

        for filename in self.dump_filenames:
            trace = self.run_perf_script(filename)
            self.traces.append(trace)

        for f in self.failures:
            syscall = SyscallInfo.get_name(f['syscall_nr'])
            err_msg = ErrorcodeInfo.get_name(f['err'])
            pid = f['pid']
            pr_msg(f'[{pid}] syscall {syscall} failed with {err_msg} [{f["err"]}]', level='INFO')

        self.save_failures("intel-pt")
        self.cleanup()

        return collected

    @staticmethod
    def cpu_supports_pt() -> bool:
        # Simple test, perf will deal with more complicated situations later
        try:
            with open('/proc/cpuinfo') as f:
                for l in f:
                    if l.startswith('flags'):
                        return 'intel_pt' in l.split(' ')
        except Exception:
            pass
        
        return False