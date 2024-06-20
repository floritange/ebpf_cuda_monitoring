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
    u64 f;               // CUfunction
    u32 gridDimX;        // unsigned int
    u32 gridDimY;        // unsigned int
    u32 gridDimZ;        // unsigned int
    u32 blockDimX;       // unsigned int
    u32 blockDimY;       // unsigned int
    u32 blockDimZ;       // unsigned int
    u32 sharedMemBytes;  // unsigned int
    u64 hStream;         // CUstream
    u64 kernelParams;    // void**
    u64 extra;           // void**
};

BPF_HASH(cuLaunchKernelLog_map, u64, struct cuLaunchKernelLog_t);
BPF_RINGBUF_OUTPUT(cuLaunchKernel_events, 1 << 12);

int cuLaunchKernelEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuLaunchKernelLog_t cuLaunchKernelLog = {};
    cuLaunchKernelLog.pid = pid_tgid >> 32;
    cuLaunchKernelLog.tid = pid_tgid;
    cuLaunchKernelLog.time_start = bpf_ktime_get_ns();
    cuLaunchKernelLog.f = PT_REGS_PARM1(ctx);
    cuLaunchKernelLog.gridDimX = PT_REGS_PARM2(ctx);
    cuLaunchKernelLog.gridDimY = PT_REGS_PARM3(ctx);
    cuLaunchKernelLog.gridDimZ = PT_REGS_PARM4(ctx);
    bpf_probe_read(&cuLaunchKernelLog.blockDimX, sizeof(u32), (void *)PT_REGS_SP(ctx) + 8);
    bpf_probe_read(&cuLaunchKernelLog.blockDimY, sizeof(u32), (void *)PT_REGS_SP(ctx) + 12);
    bpf_probe_read(&cuLaunchKernelLog.blockDimZ, sizeof(u32), (void *)PT_REGS_SP(ctx) + 16);
    bpf_probe_read(&cuLaunchKernelLog.sharedMemBytes, sizeof(u32), (void *)PT_REGS_SP(ctx) + 20);
    bpf_probe_read(&cuLaunchKernelLog.hStream, sizeof(u64), (void *)PT_REGS_SP(ctx) + 24);
    bpf_probe_read(&cuLaunchKernelLog.kernelParams, sizeof(u64), (void *)PT_REGS_SP(ctx) + 32);
    bpf_probe_read(&cuLaunchKernelLog.extra, sizeof(u64), (void *)PT_REGS_SP(ctx) + 40);

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
        cuLaunchKernelLog->time_end = bpf_ktime_get_ns();
        cuLaunchKernel_events.ringbuf_submit(cuLaunchKernelLog, 0);
    } else {
        bpf_trace_printk("cuLaunchKernelExited: Not found cuLaunchKernelLog");
    };
    return 0;
};

/*
    cuMemFree_v2
 */
struct cuMemFree_v2Log_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    void *devPtr;  // CUdeviceptr
};

BPF_HASH(cuMemFree_v2Log_map, u64, struct cuMemFree_v2Log_t);
BPF_RINGBUF_OUTPUT(cuMemFree_v2_events, 1 << 12);

int cuMemFree_v2Entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemFree_v2Log_t cuMemFree_v2Log = {};
    cuMemFree_v2Log.pid = pid_tgid >> 32;
    cuMemFree_v2Log.tid = pid_tgid;
    cuMemFree_v2Log.time_start = bpf_ktime_get_ns();
    cuMemFree_v2Log.devPtr = (void *)PT_REGS_PARM1(ctx);

    cuMemFree_v2Log_map.update(&pid_tgid, &cuMemFree_v2Log);
    return 0;
};

int cuMemFree_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemFree_v2Log_t *cuMemFree_v2Log_ptr = cuMemFree_v2Log_map.lookup(&pid_tgid);

    if (cuMemFree_v2Log_ptr != NULL) {
        struct cuMemFree_v2Log_t *cuMemFree_v2Log = cuMemFree_v2_events.ringbuf_reserve(sizeof(struct cuMemFree_v2Log_t));
        if (!cuMemFree_v2Log)
            return 0;
        *cuMemFree_v2Log = *cuMemFree_v2Log_ptr;
        cuMemFree_v2Log->time_end = bpf_ktime_get_ns();
        if (!cuMemFree_v2Log->devPtr) {
            cuMemFree_v2Log->devPtr = (void *)PT_REGS_PARM1(ctx);
        }
        cuMemFree_v2_events.ringbuf_submit(cuMemFree_v2Log, 0);
    } else {
        bpf_trace_printk("cuMemFree_v2Exit: Not found cuMemFree_v2Log");
    };
    return 0;
};

/*
    cuMemcpyHtoDAsync_v2
 */

struct cuMemcpyHtoDAsync_v2Log_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    void *dstDevice;  // CUdeviceptr
    const void *srcHost;
    size_t ByteCount;
    u64 hStream;  // CUstream
};

BPF_HASH(cuMemcpyHtoDAsync_v2Log_map, u64, struct cuMemcpyHtoDAsync_v2Log_t);
BPF_RINGBUF_OUTPUT(cuMemcpyHtoDAsync_v2_events, 1 << 12);

int cuMemcpyHtoDAsync_v2Entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyHtoDAsync_v2Log_t cuMemcpyHtoDAsync_v2Log = {};
    cuMemcpyHtoDAsync_v2Log.pid = pid_tgid >> 32;
    cuMemcpyHtoDAsync_v2Log.tid = pid_tgid;
    cuMemcpyHtoDAsync_v2Log.time_start = bpf_ktime_get_ns();
    cuMemcpyHtoDAsync_v2Log.dstDevice = (void *)PT_REGS_PARM1(ctx);
    cuMemcpyHtoDAsync_v2Log.srcHost = (const void *)PT_REGS_PARM2(ctx);
    cuMemcpyHtoDAsync_v2Log.ByteCount = (size_t)PT_REGS_PARM3(ctx);
    cuMemcpyHtoDAsync_v2Log.hStream = (u64)PT_REGS_PARM4(ctx);

    cuMemcpyHtoDAsync_v2Log_map.update(&pid_tgid, &cuMemcpyHtoDAsync_v2Log);
    return 0;
};

int cuMemcpyHtoDAsync_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyHtoDAsync_v2Log_t *cuMemcpyHtoDAsync_v2Log_ptr = cuMemcpyHtoDAsync_v2Log_map.lookup(&pid_tgid);

    if (cuMemcpyHtoDAsync_v2Log_ptr != NULL) {
        struct cuMemcpyHtoDAsync_v2Log_t *cuMemcpyHtoDAsync_v2Log = cuMemcpyHtoDAsync_v2_events.ringbuf_reserve(sizeof(struct cuMemcpyHtoDAsync_v2Log_t));
        if (!cuMemcpyHtoDAsync_v2Log)
            return 0;
        *cuMemcpyHtoDAsync_v2Log = *cuMemcpyHtoDAsync_v2Log_ptr;
        cuMemcpyHtoDAsync_v2Log->time_end = bpf_ktime_get_ns();
        cuMemcpyHtoDAsync_v2_events.ringbuf_submit(cuMemcpyHtoDAsync_v2Log, 0);
    } else {
        bpf_trace_printk("cuMemcpyHtoDAsync_v2Exit: Not found cuMemcpyHtoDAsync_v2Log");
    };
    return 0;
};

/*
    cuMemcpyDtoHAsync_v2
 */

struct cuMemcpyDtoHAsync_v2Log_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    void *dstHost;
    void *srcDevice;  // CUdeviceptr
    size_t ByteCount;
    u64 hStream;  // CUstream
};

BPF_HASH(cuMemcpyDtoHAsync_v2Log_map, u64, struct cuMemcpyDtoHAsync_v2Log_t);
BPF_RINGBUF_OUTPUT(cuMemcpyDtoHAsync_v2_events, 1 << 12);

int cuMemcpyDtoHAsync_v2Entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyDtoHAsync_v2Log_t cuMemcpyDtoHAsync_v2Log = {};
    cuMemcpyDtoHAsync_v2Log.pid = pid_tgid >> 32;
    cuMemcpyDtoHAsync_v2Log.tid = pid_tgid;
    cuMemcpyDtoHAsync_v2Log.time_start = bpf_ktime_get_ns();
    cuMemcpyDtoHAsync_v2Log.dstHost = (void *)PT_REGS_PARM1(ctx);
    cuMemcpyDtoHAsync_v2Log.srcDevice = (void *)PT_REGS_PARM2(ctx);
    cuMemcpyDtoHAsync_v2Log.ByteCount = (size_t)PT_REGS_PARM3(ctx);
    cuMemcpyDtoHAsync_v2Log.hStream = (u64)PT_REGS_PARM4(ctx);

    cuMemcpyDtoHAsync_v2Log_map.update(&pid_tgid, &cuMemcpyDtoHAsync_v2Log);
    return 0;
};

int cuMemcpyDtoHAsync_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyDtoHAsync_v2Log_t *cuMemcpyDtoHAsync_v2Log_ptr = cuMemcpyDtoHAsync_v2Log_map.lookup(&pid_tgid);

    if (cuMemcpyDtoHAsync_v2Log_ptr != NULL) {
        struct cuMemcpyDtoHAsync_v2Log_t *cuMemcpyDtoHAsync_v2Log = cuMemcpyDtoHAsync_v2_events.ringbuf_reserve(sizeof(struct cuMemcpyDtoHAsync_v2Log_t));
        if (!cuMemcpyDtoHAsync_v2Log)
            return 0;
        *cuMemcpyDtoHAsync_v2Log = *cuMemcpyDtoHAsync_v2Log_ptr;
        cuMemcpyDtoHAsync_v2Log->time_end = bpf_ktime_get_ns();
        cuMemcpyDtoHAsync_v2_events.ringbuf_submit(cuMemcpyDtoHAsync_v2Log, 0);
    } else {
        bpf_trace_printk("cuMemcpyDtoHAsync_v2Exit: Not found cuMemcpyDtoHAsync_v2Log");
    };
    return 0;
};

/*
    cuStreamSynchronize
 */

struct cuStreamSynchronizeLog_t {
    u32 pid;
    u32 tid;
    u64 time_start;
    u64 time_end;
    u64 hStream;  // CUstream
};

BPF_HASH(cuStreamSynchronizeLog_map, u64, struct cuStreamSynchronizeLog_t);
BPF_RINGBUF_OUTPUT(cuStreamSynchronize_events, 1 << 12);

int cuStreamSynchronizeEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuStreamSynchronizeLog_t cuStreamSynchronizeLog = {};
    cuStreamSynchronizeLog.pid = pid_tgid >> 32;
    cuStreamSynchronizeLog.tid = pid_tgid;
    cuStreamSynchronizeLog.time_start = bpf_ktime_get_ns();
    cuStreamSynchronizeLog.hStream = (u64)PT_REGS_PARM1(ctx);

    cuStreamSynchronizeLog_map.update(&pid_tgid, &cuStreamSynchronizeLog);
    return 0;
};

int cuStreamSynchronizeExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuStreamSynchronizeLog_t *cuStreamSynchronizeLog_ptr = cuStreamSynchronizeLog_map.lookup(&pid_tgid);

    if (cuStreamSynchronizeLog_ptr != NULL) {
        struct cuStreamSynchronizeLog_t *cuStreamSynchronizeLog = cuStreamSynchronize_events.ringbuf_reserve(sizeof(struct cuStreamSynchronizeLog_t));
        if (!cuStreamSynchronizeLog)
            return 0;
        *cuStreamSynchronizeLog = *cuStreamSynchronizeLog_ptr;
        cuStreamSynchronizeLog->time_end = bpf_ktime_get_ns();
        cuStreamSynchronize_events.ringbuf_submit(cuStreamSynchronizeLog, 0);
    } else {
        bpf_trace_printk("cuStreamSynchronizeExit: Not found cuStreamSynchronizeLog");
    };
    return 0;
};