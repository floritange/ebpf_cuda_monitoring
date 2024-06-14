#include <uapi/linux/ptrace.h>

struct cuMemAlloc_v2Log_t {
    u64 pid_tgid;
    void **devPtrPtr;  // entry address parameter
    void *devPtr;      // exited parsing address parameter
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cuMemFree_v2Log_t {
    u64 pid_tgid;
    void *devPtr;
    u64 time_start;
    u64 time_end;
};

struct cuMemcpyHtoDAsync_v2Log_t {
    u64 pid_tgid;
    void *dst_address;
    const void *src_address;
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cuMemcpyDtoHAsync_v2Log_t {
    u64 pid_tgid;
    void *dst_address;
    const void *src_address;
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cuStreamSynchronizeLog_t {
    u64 pid_tgid;
    u64 stream;
    u64 time_start;
    u64 time_end;
};

struct cuLaunchKernelLog_t {
    u64 pid_tgid;
    const void *func;
    u64 stream;
    u64 time_start;
    u64 time_end;
};

BPF_HASH(cuMemAlloc_v2Log_map, u64, struct cuMemAlloc_v2Log_t);
BPF_HASH(cuMemFree_v2Log_map, u64, struct cuMemFree_v2Log_t);
BPF_HASH(cuMemcpyHtoDAsync_v2Log_map, u64, struct cuMemcpyHtoDAsync_v2Log_t);
BPF_HASH(cuMemcpyDtoHAsync_v2Log_map, u64, struct cuMemcpyDtoHAsync_v2Log_t);
BPF_HASH(cuStreamSynchronizeLog_map, u64, struct cuStreamSynchronizeLog_t);
BPF_HASH(cuLaunchKernelLog_map, u64, struct cuLaunchKernelLog_t);

int cuMemAlloc_v2Entry(struct pt_regs *ctx) {
    void **devPtr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemAlloc_v2Log_t cuMemAlloc_v2Log = {};
    cuMemAlloc_v2Log.devPtrPtr = devPtr;
    cuMemAlloc_v2Log.devPtr = devPtr;
    cuMemAlloc_v2Log.size = size;
    cuMemAlloc_v2Log.time_start = bpf_ktime_get_ns();
    cuMemAlloc_v2Log.pid_tgid = pid_tgid;
    cuMemAlloc_v2Log_map.update(&pid_tgid, &cuMemAlloc_v2Log);
    return 0;
};

int cuMemAlloc_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemAlloc_v2Log_t *cuMemAlloc_v2Log_ptr = cuMemAlloc_v2Log_map.lookup(&pid_tgid);
    if (cuMemAlloc_v2Log_ptr != NULL) {
        struct cuMemAlloc_v2Log_t cuMemAlloc_v2Log = *cuMemAlloc_v2Log_ptr;
        cuMemAlloc_v2Log.devPtr = *cuMemAlloc_v2Log.devPtrPtr;
        cuMemAlloc_v2Log.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuMemAlloc_v2Exited success. devPtr:%p, size:%u", cuMemAlloc_v2Log.devPtr, cuMemAlloc_v2Log.size);
        // bpf_trace_printk("cuMemAlloc_v2Exited success. time_start:%llu, time_end:%llu", cuMemAlloc_v2Log.time_start, cuMemAlloc_v2Log.time_end);
        u64 devPtr_key = (u64)cuMemAlloc_v2Log.devPtr;
        cuMemAlloc_v2Log_map.delete(&pid_tgid);
        cuMemAlloc_v2Log_map.update(&devPtr_key, &cuMemAlloc_v2Log);
    } else {
        bpf_trace_printk("cuMemAlloc_v2Exited: Not found cuMemAlloc_v2Log");
    };
    return 0;
};

int cuMemFree_v2Entry(struct pt_regs *ctx) {
    void *devPtr = (void *)PT_REGS_PARM1(ctx);
    u64 devPtr_key = (u64)devPtr;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemFree_v2Log_t cuMemFree_v2Log = {
        .devPtr = devPtr,
        .time_start = bpf_ktime_get_ns(),
        .pid_tgid = pid_tgid};
    cuMemFree_v2Log_map.update(&pid_tgid, &cuMemFree_v2Log);
    return 0;
};

int cuMemFree_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemFree_v2Log_t *cuMemFree_v2Log_ptr = cuMemFree_v2Log_map.lookup(&pid_tgid);
    if (cuMemFree_v2Log_ptr != NULL) {
        struct cuMemFree_v2Log_t cuMemFree_v2Log = *cuMemFree_v2Log_ptr;
        cuMemFree_v2Log.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuMemFree_v2Exited success. devPtr:%p", cuMemFree_v2Log.devPtr);
        // bpf_trace_printk("cuMemFree_v2Exited success. time_start:%llu, time_end:%llu", cuMemFree_v2Log.time_start, cuMemFree_v2Log.time_end);
        cuMemFree_v2Log_map.delete(&pid_tgid);
    } else {
        bpf_trace_printk("cuMemFree_v2Exited: Not found cuMemFree_v2Log");
    };
    return 0;
};

int cuMemcpyHtoDAsync_v2Entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *dst_address = (void *)PT_REGS_PARM1(ctx);
    const void *src_address = (const void *)PT_REGS_PARM2(ctx);
    size_t count_size = PT_REGS_PARM3(ctx);
    struct cuMemcpyHtoDAsync_v2Log_t cuMemcpyHtoDAsync_v2Log = {
        .pid_tgid = pid_tgid,
        .dst_address = dst_address,
        .src_address = src_address,
        .size = count_size,
        .time_start = bpf_ktime_get_ns()};
    cuMemcpyHtoDAsync_v2Log_map.update(&pid_tgid, &cuMemcpyHtoDAsync_v2Log);
    return 0;
};

int cuMemcpyHtoDAsync_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyHtoDAsync_v2Log_t *cuMemcpyHtoDAsync_v2Log_ptr = cuMemcpyHtoDAsync_v2Log_map.lookup(&pid_tgid);
    if (cuMemcpyHtoDAsync_v2Log_ptr != NULL) {
        struct cuMemcpyHtoDAsync_v2Log_t cuMemcpyHtoDAsync_v2Log = *cuMemcpyHtoDAsync_v2Log_ptr;
        cuMemcpyHtoDAsync_v2Log.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuMemcpyHtoDAsync_v2Exited success. dst:%p, src:%p, size:%u", cuMemcpyHtoDAsync_v2Log.dst_address, cuMemcpyHtoDAsync_v2Log.src_address, cuMemcpyHtoDAsync_v2Log.size);
        // bpf_trace_printk("cuMemcpyHtoDAsync_v2Exited success. time_start:%llu, time_end:%llu", cuMemcpyHtoDAsync_v2Log.time_start, cuMemcpyHtoDAsync_v2Log.time_end);
        cuMemcpyHtoDAsync_v2Log_map.delete(&pid_tgid);
    } else {
        bpf_trace_printk("cuMemcpyHtoDAsync_v2Exited: Not found cuMemcpyHtoDAsync_v2Log");
    };
    return 0;
};

int cuMemcpyDtoHAsync_v2Entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *dst_address = (void *)PT_REGS_PARM1(ctx);
    const void *src_address = (const void *)PT_REGS_PARM2(ctx);
    size_t count_size = PT_REGS_PARM3(ctx);
    struct cuMemcpyDtoHAsync_v2Log_t cuMemcpyDtoHAsync_v2Log = {
        .pid_tgid = pid_tgid,
        .dst_address = dst_address,
        .src_address = src_address,
        .size = count_size,
        .time_start = bpf_ktime_get_ns()};
    cuMemcpyDtoHAsync_v2Log_map.update(&pid_tgid, &cuMemcpyDtoHAsync_v2Log);
    return 0;
};

int cuMemcpyDtoHAsync_v2Exited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuMemcpyDtoHAsync_v2Log_t *cuMemcpyDtoHAsync_v2Log_ptr = cuMemcpyDtoHAsync_v2Log_map.lookup(&pid_tgid);
    if (cuMemcpyDtoHAsync_v2Log_ptr != NULL) {
        struct cuMemcpyDtoHAsync_v2Log_t cuMemcpyDtoHAsync_v2Log = *cuMemcpyDtoHAsync_v2Log_ptr;
        cuMemcpyDtoHAsync_v2Log.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuMemcpyDtoHAsync_v2Exited success. dst:%p, src:%p, size:%u", cuMemcpyDtoHAsync_v2Log.dst_address, cuMemcpyDtoHAsync_v2Log.src_address, cuMemcpyDtoHAsync_v2Log.size);
        // bpf_trace_printk("cuMemcpyDtoHAsync_v2Exited success. time_start:%llu, time_end:%llu", cuMemcpyDtoHAsync_v2Log.time_start, cuMemcpyDtoHAsync_v2Log.time_end);
        cuMemcpyDtoHAsync_v2Log_map.delete(&pid_tgid);
    } else {
        bpf_trace_printk("cuMemcpyDtoHAsync_v2Exited: Not found cuMemcpyDtoHAsync_v2Log");
    };
    return 0;
};

int cuStreamSynchronizeEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 stream = PT_REGS_PARM1(ctx);
    struct cuStreamSynchronizeLog_t cuStreamSynchronizeLog = {
        .pid_tgid = pid_tgid,
        .stream = stream,
        .time_start = bpf_ktime_get_ns()};
    cuStreamSynchronizeLog_map.update(&pid_tgid, &cuStreamSynchronizeLog);
    return 0;
};

int cuStreamSynchronizeExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuStreamSynchronizeLog_t *cuStreamSynchronizeLog_ptr = cuStreamSynchronizeLog_map.lookup(&pid_tgid);
    if (cuStreamSynchronizeLog_ptr) {
        struct cuStreamSynchronizeLog_t cuStreamSynchronizeLog = *cuStreamSynchronizeLog_ptr;
        cuStreamSynchronizeLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuStreamSynchronizeExited success. stream:%u", cuStreamSynchronizeLog.stream);
        // bpf_trace_printk("cuStreamSynchronizeExited success. time_start:%llu, time_end:%llu", cuStreamSynchronizeLog.time_start, cuStreamSynchronizeLog.time_end);
    }
    return 0;
};

int cuLaunchKernelEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    const void *func = (const void *)PT_REGS_PARM1(ctx);
    u64 stream = PT_REGS_PARM6(ctx);
    struct cuLaunchKernelLog_t cuLaunchKernelLog = {
        .pid_tgid = pid_tgid,
        .func = func,
        .stream = stream,
        .time_start = bpf_ktime_get_ns()};
    cuLaunchKernelLog_map.update(&pid_tgid, &cuLaunchKernelLog);
    return 0;
};

int cuLaunchKernelExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuLaunchKernelLog_t *cuLaunchKernelLog_ptr = cuLaunchKernelLog_map.lookup(&pid_tgid);
    if (cuLaunchKernelLog_ptr) {
        struct cuLaunchKernelLog_t cuLaunchKernelLog = *cuLaunchKernelLog_ptr;
        cuLaunchKernelLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cuLaunchKernelExited success. func:%p, stream:%u", cuLaunchKernelLog.func, cuLaunchKernelLog.stream);
        // bpf_trace_printk("cuLaunchKernelExited success. time_start:%llu, time_end:%llu", cuLaunchKernelLog.time_start, cuLaunchKernelLog.time_end);
    }
    return 0;
};