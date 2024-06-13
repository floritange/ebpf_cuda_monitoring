#include <uapi/linux/ptrace.h>
enum cudaMemcpyKind {
    cudaMemcpyHostToHost = 0,
    cudaMemcpyHostToDevice = 1,
    cudaMemcpyDeviceToHost = 2,
    cudaMemcpyDeviceToDevice = 3,
    cudaMemcpyDefault = 4
};

struct cudaMallocLog_t {
    u64 pid_tgid;
    void **devPtrPtr;  // entry address parameter
    void *devPtr;      // exited parsing address parameter
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cudaFreeLog_t {
    u64 pid_tgid;
    void *devPtr;
    u64 time_start;
    u64 time_end;
};

struct cudaMemcpyAsyncLog_t {
    u64 pid_tgid;
    void *dst_address;
    const void *src_address;
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cudaStreamSynchronizeLog_t {
    u64 pid_tgid;
    u64 stream;
    u64 time_start;
    u64 time_end;
};

struct cudaLaunchKernelLog_t {
    u64 pid_tgid;
    const void *func;
    u64 stream;
    u64 time_start;
    u64 time_end;
};

BPF_HASH(cudaMallocLog_map, u64, struct cudaMallocLog_t);
BPF_HASH(cudaFreeLog_map, u64, struct cudaFreeLog_t);
BPF_HASH(cudaMemcpyAsyncLog_map, u64, struct cudaMemcpyAsyncLog_t);
BPF_HASH(cudaStreamSynchronizeLog_map, u64, struct cudaStreamSynchronizeLog_t);
BPF_HASH(cudaLaunchKernelLog_map, u64, struct cudaLaunchKernelLog_t);

int cudaMallocEntry(struct pt_regs *ctx) {
    void **devPtr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaMallocLog_t cudaMallocLog = {};
    cudaMallocLog.devPtrPtr = devPtr;
    cudaMallocLog.devPtr = devPtr;
    cudaMallocLog.size = size;
    cudaMallocLog.time_start = bpf_ktime_get_ns();
    cudaMallocLog.pid_tgid = pid_tgid;
    cudaMallocLog_map.update(&pid_tgid, &cudaMallocLog);
    return 0;
};

int cudaMallocExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaMallocLog_t *cudaMallocLog_ptr = cudaMallocLog_map.lookup(&pid_tgid);
    if (cudaMallocLog_ptr != NULL) {
        struct cudaMallocLog_t cudaMallocLog = *cudaMallocLog_ptr;
        cudaMallocLog.devPtr = *cudaMallocLog.devPtrPtr;
        cudaMallocLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaMallocExited success. devPtr:%p, size:%u", cudaMallocLog.devPtr, cudaMallocLog.size);
        // bpf_trace_printk("cudaMallocExited success. time_start:%llu, time_end:%llu", cudaMallocLog.time_start, cudaMallocLog.time_end);
        u64 devPtr_key = (u64)cudaMallocLog.devPtr;
        cudaMallocLog_map.delete(&pid_tgid);
        cudaMallocLog_map.update(&devPtr_key, &cudaMallocLog);
    } else {
        bpf_trace_printk("cudaMallocExited: Not found cudaMallocLog");
    };
    return 0;
};

int cudaFreeEntry(struct pt_regs *ctx) {
    void *devPtr = (void *)PT_REGS_PARM1(ctx);
    u64 devPtr_key = (u64)devPtr;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaFreeLog_t cudaFreeLog = {
        .devPtr = devPtr,
        .time_start = bpf_ktime_get_ns(),
        .pid_tgid = pid_tgid};
    cudaFreeLog_map.update(&pid_tgid, &cudaFreeLog);
    return 0;
};

int cudaFreeExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaFreeLog_t *cudaFreeLog_ptr = cudaFreeLog_map.lookup(&pid_tgid);
    if (cudaFreeLog_ptr != NULL) {
        struct cudaFreeLog_t cudaFreeLog = *cudaFreeLog_ptr;
        cudaFreeLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaFreeExited success. devPtr:%p", cudaFreeLog.devPtr);
        // bpf_trace_printk("cudaFreeExited success. time_start:%llu, time_end:%llu", cudaFreeLog.time_start, cudaFreeLog.time_end);
        cudaFreeLog_map.delete(&pid_tgid);
    } else {
        bpf_trace_printk("cudaFreeExited: Not found cudaFreeLog");
    };
    return 0;
};

int cudaMemcpyAsyncEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *dst_address = (void *)PT_REGS_PARM1(ctx);
    const void *src_address = (const void *)PT_REGS_PARM2(ctx);
    size_t count_size = PT_REGS_PARM3(ctx);
    enum cudaMemcpyKind kind = PT_REGS_PARM4(ctx);
    struct cudaMemcpyAsyncLog_t cudaMemcpyAsyncLog = {
        .pid_tgid = pid_tgid,
        .dst_address = dst_address,
        .src_address = src_address,
        .size = count_size,
        .time_start = bpf_ktime_get_ns()};
    cudaMemcpyAsyncLog_map.update(&pid_tgid, &cudaMemcpyAsyncLog);
    return 0;
};

int cudaMemcpyAsyncExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaMemcpyAsyncLog_t *cudaMemcpyAsyncLog_ptr = cudaMemcpyAsyncLog_map.lookup(&pid_tgid);
    if (cudaMemcpyAsyncLog_ptr != NULL) {
        struct cudaMemcpyAsyncLog_t cudaMemcpyAsyncLog = *cudaMemcpyAsyncLog_ptr;
        cudaMemcpyAsyncLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaMemcpyAsyncExited success. dst:%p, src:%p, size:%u", cudaMemcpyAsyncLog.dst_address, cudaMemcpyAsyncLog.src_address, cudaMemcpyAsyncLog.size);
        // bpf_trace_printk("cudaMemcpyAsyncExited success. time_start:%llu, time_end:%llu", cudaMemcpyAsyncLog.time_start, cudaMemcpyAsyncLog.time_end);
        cudaMemcpyAsyncLog_map.delete(&pid_tgid);
    } else {
        bpf_trace_printk("cudaMemcpyAsyncExited: Not found cudaMemcpyAsyncLog");
    };
    return 0;
};

int cudaStreamSynchronizeEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 stream = PT_REGS_PARM1(ctx);
    struct cudaStreamSynchronizeLog_t cudaStreamSynchronizeLog = {
        .pid_tgid = pid_tgid,
        .stream = stream,
        .time_start = bpf_ktime_get_ns()};
    cudaStreamSynchronizeLog_map.update(&pid_tgid, &cudaStreamSynchronizeLog);
    return 0;
};

int cudaStreamSynchronizeExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaStreamSynchronizeLog_t *cudaStreamSynchronizeLog_ptr = cudaStreamSynchronizeLog_map.lookup(&pid_tgid);
    if (cudaStreamSynchronizeLog_ptr) {
        struct cudaStreamSynchronizeLog_t cudaStreamSynchronizeLog = *cudaStreamSynchronizeLog_ptr;
        cudaStreamSynchronizeLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaStreamSynchronizeExited success. stream:%u", cudaStreamSynchronizeLog.stream);
        // bpf_trace_printk("cudaStreamSynchronizeExited success. time_start:%llu, time_end:%llu", cudaStreamSynchronizeLog.time_start, cudaStreamSynchronizeLog.time_end);
    }
    return 0;
};

int cudaLaunchKernelEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    const void *func = (const void *)PT_REGS_PARM1(ctx);
    u64 stream = PT_REGS_PARM6(ctx);
    struct cudaLaunchKernelLog_t cudaLaunchKernelLog = {
        .pid_tgid = pid_tgid,
        .func = func,
        .stream = stream,
        .time_start = bpf_ktime_get_ns()};
    cudaLaunchKernelLog_map.update(&pid_tgid, &cudaLaunchKernelLog);
    return 0;
};

int cudaLaunchKernelExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaLaunchKernelLog_t *cudaLaunchKernelLog_ptr = cudaLaunchKernelLog_map.lookup(&pid_tgid);
    if (cudaLaunchKernelLog_ptr) {
        struct cudaLaunchKernelLog_t cudaLaunchKernelLog = *cudaLaunchKernelLog_ptr;
        cudaLaunchKernelLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaLaunchKernelExited success. func:%p, stream:%u", cudaLaunchKernelLog.func, cudaLaunchKernelLog.stream);
        // bpf_trace_printk("cudaLaunchKernelExited success. time_start:%llu, time_end:%llu", cudaLaunchKernelLog.time_start, cudaLaunchKernelLog.time_end);
    }
    return 0;
};

int cuLaunchKernelEntry(struct pt_regs *ctx) {
    u64 func_addr = PT_REGS_PARM1(ctx);
    char func_name[64];
    bpf_trace_printk("cuLaunchKernelEntry success. %s", func_name);
    return 0;
};

int cuMemFree_v2Entry(struct pt_regs *ctx) {
    bpf_trace_printk("cuMemFree_v2Entry success.");
    return 0;
};

int cuMemAlloc_v2Entry(struct pt_regs *ctx) {
    bpf_trace_printk("cuMemAlloc_v2Entry success.");
    return 0;
};

int cuMemcpyHtoDAsync_v2Entry(struct pt_regs *ctx) {
    bpf_trace_printk("cuMemcpyHtoDAsync_v2Entry success.");
    return 0;
};

int cuStreamSynchronizeEntry(struct pt_regs *ctx) {
    bpf_trace_printk("cuStreamSynchronizeEntry success.");
    return 0;
};