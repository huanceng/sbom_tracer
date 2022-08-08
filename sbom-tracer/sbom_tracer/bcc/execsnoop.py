#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function

import argparse
import json
import time
from collections import defaultdict

from sbom_tracer.util.compat import decode

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF

# arguments
examples = """examples:
    ./execsnoop           # trace all exec() syscalls
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--task-id")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define MAXARG  64
#define ENVSIZE  128
#define MAXENV  96
#define MAXDEPTH 32

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
    char env[ENVSIZE];
    u32 ancestor_pids[MAXDEPTH];
};

BPF_PERF_OUTPUT(events);

static int submit_env(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *env = NULL;
    bpf_probe_read(&env, sizeof(env), ptr);
    if (env) {
        bpf_probe_read(data->env, sizeof(data->env), env);
        events.perf_submit(ctx, data, sizeof(struct data_t));
        return 1;
    }
    return 0;
}

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

static void get_ancestor_pids(struct task_struct *task, u32 *ancestor_pids)
{
    #pragma unroll
    for (int i = 0; i < MAXDEPTH; i++)
    {
        if (task->tgid == 1 || task->tgid == 0)
            break;
        ancestor_pids[i] = task->tgid;
        task = task->real_parent;
    }
}


int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    
    #pragma unroll
    for (int i = 0; i < MAXENV; i++) {
        if (submit_env(ctx, (void *)&__envp[i], &data) == 0)
            break;
    }

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    get_ancestor_pids(task, data.ancestor_pids);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")


class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1


start_ts = time.time()
argv = defaultdict(list)
cwd = {}


# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(decode(event.argv))
        if decode(event.env).startswith("PWD="):
            cwd[event.pid] = decode(event.env).replace("PWD=", "")
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0:
            skip = True

        if not skip:
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            argv_text = ' '.join(argv[event.pid]).strip()
            print(json.dumps(dict(pid=event.pid, ppid=ppid, cmd=decode(event.comm), full_cmd=argv_text,
                                  cwd=cwd.get(event.pid), ancestor_pids=list(event.ancestor_pids))))
        try:
            del (argv[event.pid])
            del (cwd[event.pid])
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
