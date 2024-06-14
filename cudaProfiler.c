#include <uapi/linux/ptrace.h>

/*
    cuMemAlloc_v2
 */
struct cuMemAlloc_v2Log_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    void **devPtrPtr;  // entry address parameter
    void *devPtr;      // exited parsing address parameter
    size_t size;       // bytes
};

BPF_HASH(cuMemAlloc_v2Log_map, u64, struct cuMemAlloc_v2Log_t);
BPF_RINGBUF_OUTPUT(cuMemAlloc_v2_events, 1 << 12);

int cuMemAlloc_v2Entry(struct pt_regs *ctx) {
    void **devPtr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemAlloc_v2Log_t cuMemAlloc_v2Log = {};
    cuMemAlloc_v2Log.pid = pid_tgid >> 32;
    cuMemAlloc_v2Log.tid = pid_tgid;
    cuMemAlloc_v2Log.time_start = bpf_ktime_get_ns();
    cuMemAlloc_v2Log.devPtrPtr = devPtr;
    cuMemAlloc_v2Log.size = size;

    cuMemAlloc_v2Log_map.update(&pid_tgid, &cuMemAlloc_v2Log);
    return 0;
};

int cuMemAlloc_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemAlloc_v2Log_t *cuMemAlloc_v2Log_ptr = cuMemAlloc_v2Log_map.lookup(&pid_tgid);

    if (cuMemAlloc_v2Log_ptr != NULL) {
        struct cuMemAlloc_v2Log_t *cuMemAlloc_v2Log = cuMemAlloc_v2_events.ringbuf_reserve(sizeof(struct cuMemAlloc_v2Log_t));
        if (!cuMemAlloc_v2Log)
            return 0;
        *cuMemAlloc_v2Log = *cuMemAlloc_v2Log_ptr;
        cuMemAlloc_v2Log->devPtr = *cuMemAlloc_v2Log->devPtrPtr;
        cuMemAlloc_v2Log->time_end = bpf_ktime_get_ns();
        cuMemAlloc_v2_events.ringbuf_submit(cuMemAlloc_v2Log, 0);
    } else {
        bpf_trace_printk("cuMemAlloc_v2Exited: Not found cuMemAlloc_v2Log");
    };
    return 0;
};

/*
    cuLaunchKernel
 */
struct cuLaunchKernelLog_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    void **devPtrPtr;  // entry address parameter
    void *devPtr;      // exited parsing address parameter
    size_t size;       // bytes
};

BPF_HASH(cuLaunchKernelLog_map, u64, struct cuLaunchKernelLog_t);
BPF_RINGBUF_OUTPUT(cuLaunchKernel_events, 1 << 12);

int cuLaunchKernelEntry(struct pt_regs *ctx) {
    void **devPtr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuLaunchKernelLog_t cuLaunchKernelLog = {};
    cuLaunchKernelLog.pid = pid_tgid >> 32;
    cuLaunchKernelLog.tid = pid_tgid;
    cuLaunchKernelLog.time_start = bpf_ktime_get_ns();
    cuLaunchKernelLog.devPtrPtr = devPtr;
    cuLaunchKernelLog.size = size;

    cuLaunchKernelLog_map.update(&pid_tgid, &cuLaunchKernelLog);
    return 0;
};

int cuLaunchKernelExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuLaunchKernelLog_t *cuLaunchKernelLog_ptr = cuLaunchKernelLog_map.lookup(&pid_tgid);

    if (cuLaunchKernelLog_ptr != NULL) {
        struct cuLaunchKernelLog_t *cuLaunchKernelLog = cuLaunchKernel_events.ringbuf_reserve(sizeof(struct cuLaunchKernelLog_t));
        if (!cuLaunchKernelLog)
            return 0;
        *cuLaunchKernelLog = *cuLaunchKernelLog_ptr;
        cuLaunchKernelLog->devPtr = *cuLaunchKernelLog->devPtrPtr;
        cuLaunchKernelLog->time_end = bpf_ktime_get_ns();
        cuLaunchKernel_events.ringbuf_submit(cuLaunchKernelLog, 0);
    } else {
        bpf_trace_printk("cuLaunchKernelExited: Not found cuLaunchKernelLog");
    };
    return 0;
};
