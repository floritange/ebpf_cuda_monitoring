#include <uapi/linux/ptrace.h>

struct memAllocCall_t {
    void *devPtr;
    u64 pid_tgid;
};

struct memFreeLog_t {
    u32 pid;
    void *devPtr;
    u64 time_start;
};

struct memallocLog_t {
    u32 pid;
    void **devPtr;
    size_t bytes_length;
    u64 time_start;
};
struct memcpyLog_t {
    u32 pid;
    size_t bytes_length;
    u8 kind;
    u64 time_start;
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
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cudaMemcpyAsyncLog_t {
    u64 pid_tgid;
    void *devPtr;
    size_t size;
    u64 time_start;
    u64 time_end;
};

struct cudaStreamIsCapturingLog_t {
    u64 pid_tgid;
    void **devPtrPtr;
    void *devPtr;
};

struct dim3 {
    u64 x;
    u64 y;
    u64 z;
};

struct cudaStream_t {
    u64 dummy;
};

BPF_HASH(memallocLogHash, u64, struct memallocLog_t);
BPF_HASH(memcpyHash, u64, struct memcpyLog_t);
BPF_HASH(memFreeHash, u64, struct memFreeLog_t);
// key: pid_tgid
// value: memory owned, bytes
BPF_HASH(memOwnedHash, u64, u64);

// used to trace cudaMemalloc-cudaFree pairs
BPF_HASH(memOwnedPairs, struct memAllocCall_t, u64);

BPF_HASH(cudaMallocLog_map, u64, struct cudaMallocLog_t);
BPF_HASH(cudaFreeLog_map, u64, struct cudaFreeLog_t);
BPF_HASH(cudaMemcpyAsyncLog_map, u64, struct cudaMemcpyAsyncLog_t);
BPF_HASH(cudaStreamIsCapturingLog_map, u64, struct cudaStreamIsCapturingLog_t);

// int cudaGetDeviceEntry(struct pt_regs *ctx) {
//     int *device = (int *)PT_REGS_PARM1(ctx);
//     // -1, 0 is inital
//     // bpf_trace_printk("cudaGetDevice entered, device: %d", *device);
//     return 0;
// };

// int cudaGetDeviceExited(struct pt_regs *ctx) {
//     int *device = (int *)PT_REGS_PARM1(ctx);
//     bpf_trace_printk("cudaGetDeviceExited, device: %d", *device);
//     return 0;
// };

// int cudaGetLastErrorEntry(struct pt_regs *ctx) {
//     return 0;
// }

// int cudaGetLastErrorExited(struct pt_regs *ctx) {
//     u32 ret = (u32)PT_REGS_RC(ctx);
//     char msg[64];
//     bpf_probe_read_user(&msg, sizeof(msg), &ret);
//     bpf_trace_printk("cudaGetLastError Exited. Return code: %u\n", ret);
//     return 0;
// }

int cudaLaunchKernelEntry(struct pt_regs *ctx) {
    const void *func = (const void *)PT_REGS_PARM1(ctx);
    struct dim3 gridDim;
    struct dim3 blockDim;
    bpf_probe_read_kernel(&gridDim, sizeof(gridDim), (void *)PT_REGS_PARM2(ctx));
    bpf_probe_read_kernel(&blockDim, sizeof(blockDim), (void *)PT_REGS_PARM3(ctx));
    void **args = (void **)PT_REGS_PARM4(ctx);
    size_t sharedMem = (size_t)PT_REGS_PARM5(ctx);
    u64 stream = PT_REGS_PARM6(ctx);
    // bpf_probe_read_kernel(&stream, sizeof(stream), (void *)PT_REGS_PARM6(ctx));
    bpf_trace_printk("cudaLaunchKernelEntry. func: %p.", func);
    bpf_trace_printk("cudaLaunchKernelEntry. gridDim: (%u, %u, %u).", gridDim.x, gridDim.y, gridDim.z);
    bpf_trace_printk("cudaLaunchKernelEntry. blockDim: (%u, %u, %u).", blockDim.x, blockDim.y, blockDim.z);
    bpf_trace_printk("cudaLaunchKernelEntry. sharedMem: %d, stream: %u.", sharedMem, stream);
    return 0;
};

// int cudaLaunchKernelExited(struct pt_regs *ctx) {
//     const void *func = (const void *)PT_REGS_PARM1(ctx);
//     struct dim3 gridDim;
//     struct dim3 blockDim;
//     bpf_probe_read_kernel(&gridDim, sizeof(gridDim), (void *)PT_REGS_PARM2(ctx));
//     bpf_probe_read_kernel(&blockDim, sizeof(blockDim), (void *)PT_REGS_PARM3(ctx));
//     void **args = (void **)PT_REGS_PARM4(ctx);
//     size_t sharedMem = (size_t)PT_REGS_PARM5(ctx);
//     struct cudaStream_t stream;
//     bpf_probe_read_kernel(&stream, sizeof(stream), (void *)PT_REGS_PARM6(ctx));
//     return 0;
// };

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
        bpf_trace_printk("cudaMallocExited success. devPtr:%p, size:%u, pid_tgid:%u", cudaMallocLog.devPtr, cudaMallocLog.size, pid_tgid);
        bpf_trace_printk("cudaMallocExited success. start_time:%u, end_time:%u", cudaMallocLog.time_start, cudaMallocLog.time_end);
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
    struct cudaMallocLog_t *cudaMallocLog_ptr = cudaMallocLog_map.lookup(&devPtr_key);
    if (cudaMallocLog_ptr != NULL) {
        struct cudaMallocLog_t cudaMallocLog = *cudaMallocLog_ptr;
        struct cudaFreeLog_t cudaFreeLog = {
            .devPtr = devPtr,
            .size = cudaMallocLog.size,
            .time_start = bpf_ktime_get_ns(),
            .pid_tgid = pid_tgid};
        cudaFreeLog_map.update(&pid_tgid, &cudaFreeLog);
    } else {
        bpf_trace_printk("cudaFreeEntry: Not found cudaMallocLog");
    }
    return 0;
};

int cudaFreeExited(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaFreeLog_t *cudaFreeLog_ptr = cudaFreeLog_map.lookup(&pid_tgid);
    if (cudaFreeLog_ptr != NULL) {
        struct cudaFreeLog_t cudaFreeLog = *cudaFreeLog_ptr;
        cudaFreeLog.time_end = bpf_ktime_get_ns();
        bpf_trace_printk("cudaFreeExited success. devPtr:%p, size:%u, pid_tgid:%u", cudaFreeLog.devPtr, cudaFreeLog.size, pid_tgid);
        bpf_trace_printk("cudaFreeExited success. start_time:%u, end_time:%u", cudaFreeLog.time_start, cudaFreeLog.time_end);
        u64 devPtr_key = (u64)cudaFreeLog.devPtr;
        cudaFreeLog_map.delete(&pid_tgid);
        cudaFreeLog_map.update(&devPtr_key, &cudaFreeLog);
    } else {
        bpf_trace_printk("cudaFreeExited: Not found cudaFreeLog");
    };
    return 0;
};

int cudaMemcpyAsyncEntry(struct pt_regs *ctx) {
    void *dst_address = (void *)PT_REGS_PARM1(ctx);
    const void *src_address = (const void *)PT_REGS_PARM2(ctx);
    size_t count_size = PT_REGS_PARM3(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cudaMemcpyAsyncLog_t cudaMemcpyAsyncLog = {
        .pid_tgid = pid_tgid,
        .devPtr = dst_address,
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
        bpf_trace_printk("cudaMemcpyAsyncExited success. devPtr:%p, size:%u, pid_tgid:%u", cudaMemcpyAsyncLog.devPtr, cudaMemcpyAsyncLog.size, pid_tgid);
        bpf_trace_printk("cudaMemcpyAsyncExited success. start_time:%u, end_time:%u", cudaMemcpyAsyncLog.time_start, cudaMemcpyAsyncLog.time_end);
        u64 devPtr_key = (u64)cudaMemcpyAsyncLog.devPtr;
        cudaMemcpyAsyncLog_map.delete(&pid_tgid);
        cudaMemcpyAsyncLog_map.update(&devPtr_key, &cudaMemcpyAsyncLog);
    } else {
        bpf_trace_printk("cudaMemcpyAsyncExited: Not found cudaMemcpyAsyncLog");
    };
    return 0;
};

// int cudaStreamIsCapturingEntry(struct pt_regs *ctx) {
//     u64 stream = PT_REGS_PARM1(ctx);
//     void **pCaptureStatus = (void **)PT_REGS_PARM2(ctx);
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     struct cudaStreamIsCapturingLog_t cudaStreamIsCapturingLog = {
//         .pid_tgid = pid_tgid,
//         .devPtrPtr = pCaptureStatus};
//     cudaStreamIsCapturingLog_map.update(&pid_tgid, &cudaStreamIsCapturingLog);
//     bpf_trace_printk("cudaStreamIsCapturingEntry. stream:%u, pCaptureStatus:%p", stream, pCaptureStatus);
//     return 0;
// };

// int cudaStreamIsCapturingExited(struct pt_regs *ctx) {
//     int ret = PT_REGS_RC(ctx);
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     struct cudaStreamIsCapturingLog_t *cudaStreamIsCapturingLog_ptr = cudaStreamIsCapturingLog_map.lookup(&pid_tgid);
//     if (cudaStreamIsCapturingLog_ptr != NULL) {
//         struct cudaStreamIsCapturingLog_t cudaStreamIsCapturingLog;
//         bpf_probe_read_user(&cudaStreamIsCapturingLog, sizeof(cudaStreamIsCapturingLog), cudaStreamIsCapturingLog_ptr);
//         bpf_probe_read_user(&cudaStreamIsCapturingLog.devPtr, sizeof(cudaStreamIsCapturingLog.devPtr), cudaStreamIsCapturingLog.devPtrPtr);
//         bpf_trace_printk("cudaStreamIsCapturingExited. ret:%d, pCaptureStatus:%p", ret, cudaStreamIsCapturingLog.devPtr);
//     } else {
//         bpf_trace_printk("cudaStreamIsCapturingLog_ptr is NULL.");
//     }
//     return 0;
// };

// int cudaStreamSynchronizeEntry(struct pt_regs *ctx) {
//     u64 stream = PT_REGS_PARM1(ctx);
//     bpf_trace_printk("cudaStreamSynchronizeEntry. stream:%u", stream);
//     return 0;
// };

// int cudaStreamSynchronizeExited(struct pt_regs *ctx) {
//         u64 stream = PT_REGS_PARM1(ctx);
//     bpf_trace_printk("cudaStreamSynchronizeExited. stream:%u", stream);
//     return 0;
// };

int cuInitEntry(struct pt_regs *ctx) {
    unsigned int Flags = PT_REGS_PARM1(ctx);
    bpf_trace_printk("cuInitEntry. Flags:%u", Flags);
    return 0;
};