// Copyright 2023 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
//#include <bpf/bpf_helpers.h>
#include <bcc/proto.h>

#define KEY_SYSCALL_NR 1
#define KEY_ERROR_CODE 2
#define KEY_PARENT_PID 3
#define KEY_OCCUR_TIMES 4
#define KEY_FLAGS 5

#define STOP_ON_ERROR	(1ull << 0)

#define MIN_ERROR	((unsigned long)(-1024))

#if 0
// Just as a record to the filter format
struct syscall_filter_t {
    u64 syscall_nr;
    u64 error_code;
    u64 parent_pid;
};
#endif

struct syscall_event_t {
    u64 pid;
    u64 syscall_nr;
    u64 syscall_ret;
    u64 ts;
};

BPF_PERF_OUTPUT(syscall_events);
BPF_HASH(config_map, u64, u64);

struct loop_ctx {
    struct task_struct *task;
    u64 parent_pid;
    u32 is_parent;
};

static inline u64 check_parent(u32 loop_idx, struct loop_ctx *loop_ctx) {
    struct task_struct *task = loop_ctx->task;

    if (task == NULL)
        return 1;

    if (task->tgid == loop_ctx->parent_pid) {
        loop_ctx->is_parent = 1;
        return 1;
    }

    if (task->pid == 1)
        return 0;

    task = (struct task_struct *)task->real_parent;
    loop_ctx->task = task;
    return 0;
}

static inline int is_descendant(u64 pid, u64 parent_pid) {
    struct loop_ctx loop_ctx;
    int i;

    loop_ctx.task = (struct task_struct *)bpf_get_current_task();
    loop_ctx.parent_pid = parent_pid;
    loop_ctx.is_parent = 0;

    //result = bpf_loop(1ul << 29, check_parent, (void *)(long)&loop_ctx, 0);
    for (i = 0; i < 64; i++) {
        check_parent(i, &loop_ctx);
    }

    return loop_ctx.is_parent;
}

int trace_syscalls(struct tracepoint__raw_syscalls__sys_exit *args) {
    struct syscall_event_t event = {};
    u64 syscall_nr_req, error_code_req, parent_pid, occur_times, flags;
    u64 pid = bpf_get_current_pid_tgid() >> 32;

    u64 key_syscall_nr = KEY_SYSCALL_NR;
    u64 key_error_code = KEY_ERROR_CODE;
    u64 key_parent_pid = KEY_PARENT_PID;
    u64 key_occur_times = KEY_OCCUR_TIMES;
    u64 key_flags = KEY_FLAGS;

    u64 *syscall_nr_ptr = config_map.lookup(&key_syscall_nr);
    u64 *error_code_ptr = config_map.lookup(&key_error_code);
    u64 *parent_pid_ptr = config_map.lookup(&key_parent_pid);
    u64 *occur_times_ptr = config_map.lookup(&key_occur_times);
    u64 *flags_ptr = config_map.lookup(&key_flags);

    u64 syscall_nr = args->id;
    u64 syscall_ret = args->ret;

    if (!syscall_nr_ptr || !error_code_ptr || !parent_pid_ptr || !occur_times_ptr || !flags_ptr)
        return 0;
    
    syscall_nr_req = *syscall_nr_ptr;
    error_code_req = *error_code_ptr;
    parent_pid = *parent_pid_ptr;

    if (syscall_nr != syscall_nr_req && syscall_nr_req != -1ull)
        return 0;

    if (syscall_ret < MIN_ERROR)
    	return 0;

    if (syscall_ret != error_code_req && error_code_req != -1ull)
        return 0;

    if (parent_pid != -1ull && !is_descendant(pid, parent_pid))
        return 0;

    occur_times = *occur_times_ptr;
    if (occur_times != -1ull) {
        if (occur_times == 0)
            return 0;

        occur_times--;
        config_map.update(&key_occur_times, &occur_times);

        if (occur_times != 0)
            return 0;
    }

    event.pid = pid;
    event.syscall_nr = syscall_nr;
    event.syscall_ret = syscall_ret;
    event.ts = bpf_ktime_get_ns();
    syscall_events.perf_submit(args, &event, sizeof(event));

    flags = *flags_ptr;
    if (flags & STOP_ON_ERROR)
        bpf_send_signal(SIGSTOP);

    return 0;
}
