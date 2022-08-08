#!/usr/bin/python
#
# sslsniff  Captures data on read/recv or write/send functions of OpenSSL,
#           GnuTLS and NSS
#           For Linux, uses BCC, eBPF.
#
# USAGE: sslsniff.py [-h]
#

from __future__ import print_function

import argparse
import json

from sbom_tracer.util.compat import decode

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF

# arguments
examples = """examples:
    ./sslsniff              # sniff OpenSSL and GnuTLS functions
"""
parser = argparse.ArgumentParser(
    description="Sniff SSL data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--task-id")
args = parser.parse_args()

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#define MAX_BUF_SIZE 8192
struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        u32 ppid;
        u32 tid;
        u32 uid;
        u32 len;
        int buf_filled;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};
#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))
BPF_PERCPU_ARRAY(ssl_data, struct probe_SSL_data_t, 1);
BPF_PERF_OUTPUT(perf_SSL_write);
int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;
        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data->ppid = task->real_parent->tgid;
        data->tid = tid;
        data->uid = uid;
        data->len = num;
        data->buf_filled = 0;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)num);
        if (buf != 0)
                ret = bpf_probe_read(data->buf, buf_copy_size, buf);
        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;
        perf_SSL_write.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}
"""

b = BPF(text=prog)


def attach_without_exc(name, sym):
    try:
        b.attach_uprobe(name=name, sym=sym, fn_name="probe_SSL_write", pid=-1)
    except:
        pass


ssl_list = [("ssl", "SSL_write"), ("gnutls", "gnutls_record_send"), ("nspr4", "PR_Write"), ("nspr4", "PR_Send")]
for name, sym in ssl_list:
    attach_without_exc(name, sym)

max_buffer_size = 8192


def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


def print_event(cpu, data, size):
    event = b["perf_SSL_write"].event(data)

    if event.len <= max_buffer_size:
        buf_size = event.len
    else:
        buf_size = max_buffer_size

    if event.buf_filled == 1:
        buf = bytearray(event.buf[:buf_size])
    else:
        buf = b""

    ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
    print(json.dumps(dict(cmd=decode(event.comm), pid=event.pid, ppid=ppid, data=decode(buf))))


b["perf_SSL_write"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
