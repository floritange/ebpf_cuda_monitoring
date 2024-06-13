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
BPF_HASH(memallocLogHash, u64, struct memallocLog_t);
BPF_HASH(memcpyHash, u64, struct memcpyLog_t);
BPF_HASH(memFreeHash, u64, struct memFreeLog_t);
// key: pid_tgid
// value: memory owned, bytes
BPF_HASH(memOwnedHash, u64, u64);

// used to trace cudaMemalloc-cudaFree pairs
BPF_HASH(memOwnedPairs, struct memAllocCall_t, u64);

int cudaGetDeviceEntry(struct pt_regs *ctx) {
    int *device = (int *)PT_REGS_PARM1(ctx);
    // -1, 0 is inital
    // bpf_trace_printk("cudaGetDevice entered, device: %d", *device);
    return 0;
};

int cudaGetDeviceExited(struct pt_regs *ctx) {
    int *device = (int *)PT_REGS_PARM1(ctx);
    bpf_trace_printk("cudaGetDevice Exited, device: %d", *device);
    return 0;
};

int cudaGetLastErrorEntry(struct pt_regs *ctx) {
    return 0;
}

int cudaGetLastErrorExited(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    char msg[64];
    bpf_probe_read_user(&msg, sizeof(msg), &ret);
    bpf_trace_printk("cudaGetLastError Exited. Return code: %u\n", ret);
    return 0;
}

int cudaLaunchKernelEntry(struct pt_regs *ctx) {
    const void *func = (const void *)PT_REGS_PARM1(ctx);
    struct dim3 gridDim;
    struct dim3 blockDim;
    bpf_probe_read_kernel(&gridDim, sizeof(gridDim), (void *)PT_REGS_PARM2(ctx));
    bpf_probe_read_kernel(&blockDim, sizeof(blockDim), (void *)PT_REGS_PARM3(ctx));
    void **args = (void **)PT_REGS_PARM4(ctx);
    size_t sharedMem = (size_t)PT_REGS_PARM5(ctx);

    struct cudaStream_t stream;
    bpf_probe_read_kernel(&stream, sizeof(stream), (void *)PT_REGS_PARM6(ctx));
    bpf_trace_printk("cudaLaunchKernelEntry. func: %lx.", *(unsigned long *)func);
    bpf_trace_printk("cudaLaunchKernelEntry. gridDim: (%u, %u, %u).", gridDim.x, gridDim.y, gridDim.z);
    bpf_trace_printk("cudaLaunchKernelEntry. blockDim: (%u, %u, %u).", blockDim.x, blockDim.y, blockDim.z);
    bpf_trace_printk("cudaLaunchKernelEntry. sharedMem: %d, stream: %lx.", sharedMem, (unsigned long)&stream);
    return 0;
};
int cudaLaunchKernelExited(struct pt_regs *ctx) {
    const void *func = (const void *)PT_REGS_PARM1(ctx);
    struct dim3 gridDim;
    struct dim3 blockDim;
    bpf_probe_read_kernel(&gridDim, sizeof(gridDim), (void *)PT_REGS_PARM2(ctx));
    bpf_probe_read_kernel(&blockDim, sizeof(blockDim), (void *)PT_REGS_PARM3(ctx));
    void **args = (void **)PT_REGS_PARM4(ctx);
    size_t sharedMem = (size_t)PT_REGS_PARM5(ctx);

    struct cudaStream_t stream;
    bpf_probe_read_kernel(&stream, sizeof(stream), (void *)PT_REGS_PARM6(ctx));
    bpf_trace_printk("cudaLaunchKernelExited. func: %lx.", *(unsigned long *)func);
    bpf_trace_printk("cudaLaunchKernelExited. gridDim: (%u, %u, %u).", gridDim.x, gridDim.y, gridDim.z);
    bpf_trace_printk("cudaLaunchKernelExited. blockDim: (%u, %u, %u).", blockDim.x, blockDim.y, blockDim.z);
    bpf_trace_printk("cudaLaunchKernelExited. sharedMem: %d, stream: %lx.", sharedMem, (unsigned long)&stream);
    return 0;
};

int cudaMallocEntry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx) || !PT_REGS_PARM2(ctx)) {
        return 0;
    }

    struct memallocLog_t memallocLog = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    memallocLog.pid = pid;
    size_t bytes_alloc = PT_REGS_PARM2(ctx);
    memallocLog.bytes_length = bytes_alloc;
    memallocLog.devPtr = (void **)PT_REGS_PARM1(ctx);

    // bpf_probe_read_user(&memallocLog.devPtr, sizeof(memallocLog.devPtr), (void **)PT_REGS_PARM1(ctx));

    bpf_trace_printk("read devPtrPtr:%lx, alloc: %u", memallocLog.devPtr, bytes_alloc);

    memallocLog.time_start = bpf_ktime_get_ns();
    memallocLogHash.lookup_or_try_init(&pid_tgid, &memallocLog);

    return 0;
};

int cudaMallocExited(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);

    struct memallocLog_t *memallocLog;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    memallocLog = memallocLogHash.lookup(&pid_tgid);
    if (memallocLog) {
        if (ret == 0) {
            u64 time_start = memallocLog->time_start;
            u64 time_elapsed = bpf_ktime_get_ns() - time_start;
            bpf_trace_printk("Malloc success,pid %d, memory alloc %u bytes,time used:%d ns.", pid, memallocLog->bytes_length, time_elapsed);
            u64 bytes_alloc = memallocLog->bytes_length;

            void *devPtrAlloc;

            bpf_probe_read_user(&devPtrAlloc, sizeof(devPtrAlloc), (void **)memallocLog->devPtr);
            bpf_trace_printk("cudaMalloc read devPtr:%lx.", devPtrAlloc);
            struct memAllocCall_t memAllocCall = {
                .devPtr = devPtrAlloc,
                .pid_tgid = pid_tgid,
            };

            memOwnedPairs.lookup_or_try_init(&memAllocCall, &bytes_alloc);

            u64 zero = 0;

            u64 *bytes_owned = memOwnedHash.lookup_or_try_init(&pid_tgid, &zero);

            if (!bytes_owned) {
                memallocLogHash.delete(&pid_tgid);
                return 0;
            }
            *bytes_owned += bytes_alloc;

            memOwnedHash.update(&pid_tgid, bytes_owned);

            bpf_trace_printk("After Malloc, process %d have  %d bytes in memory.", pid, *bytes_owned);

            memallocLogHash.delete(&pid_tgid);
        }
    }

    return 0;
};

int cudaMemcpyAsyncEntry(struct pt_regs *ctx) {
    size_t bytes_alloc = PT_REGS_PARM3(ctx);
    void *dst_address = (void *)PT_REGS_PARM1(ctx);
    const void *src_address = (const void *)PT_REGS_PARM2(ctx);
    bpf_trace_printk("cudaMemcpyAsyncEntry entered. dst_address:%lx, src_address:%lx, bytes_alloc:%u", dst_address, src_address, bytes_alloc);
    return 0;
};

int cudaMemcpyEntry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM3(ctx) || !PT_REGS_PARM4(ctx)) {
        return 0;
    }
    bpf_trace_printk("cudaMemcpyEntry!!!!!");
    struct memcpyLog_t memcpyLog = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    memcpyLog.pid = pid;
    size_t bytes_copy = PT_REGS_PARM3(ctx);
    memcpyLog.bytes_length = bytes_copy;

    u8 cpyKind = PT_REGS_PARM4(ctx);
    memcpyLog.kind = cpyKind;
    memcpyLog.time_start = bpf_ktime_get_ns();
    memcpyHash.lookup_or_try_init(&pid_tgid, &memcpyLog);

    return 0;
};

int cudaMemcpyExited(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    bpf_trace_printk("cudaMemcpyExited!!!!!");
    struct memcpyLog_t *memcpyLog;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    memcpyLog = memcpyHash.lookup(&pid_tgid);
    if (memcpyLog) {
        if (ret == 0) {
            u64 time_start = memcpyLog->time_start;
            u64 time_elapsed = bpf_ktime_get_ns() - time_start;
            if (memcpyLog->kind == 1) {
                bpf_trace_printk("Memcpy Host -> Device success,pid %d, memory copy %u bytes,time used:%d ns.", pid, memcpyLog->bytes_length, time_elapsed);
            } else if (memcpyLog->kind == 2) {
                bpf_trace_printk("Memcpy Device -> Host success,pid %d, memory copy %u bytes,time used:%d ns.", pid, memcpyLog->bytes_length, time_elapsed);
            }
            memcpyHash.delete(&pid_tgid);
        }
    }

    return 0;
};

int cudaFreeEntry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)pid_tgid;
    u64 time_start = bpf_ktime_get_ns();
    struct memFreeLog_t memFreeLog = {};
    memFreeLog.pid = pid;
    memFreeLog.time_start = time_start;
    memFreeLog.devPtr = (void *)PT_REGS_PARM1(ctx);
    memFreeHash.lookup_or_try_init(&pid_tgid, &memFreeLog);
    return 0;
};

int cudaFreeExit(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)pid_tgid;
    struct memFreeLog_t *memFreeLog = memFreeHash.lookup(&pid_tgid);
    if (memFreeLog) {
        if (ret == 0) {
            u64 time_start = memFreeLog->time_start;
            u64 time_elapsed = bpf_ktime_get_ns() - time_start;
            bpf_trace_printk("Mem Free success, pid:%d, time used:%u ns, devPtr: %lx.", pid, time_elapsed, memFreeLog->devPtr);

            struct memAllocCall_t memAllocCall = {
                .devPtr = memFreeLog->devPtr,
                .pid_tgid = pid_tgid,
            };

            u64 *byte_alloc = memOwnedPairs.lookup(&memAllocCall);
            if (!byte_alloc) {
                memFreeHash.delete(&pid_tgid);
                return 0;
            }

            u64 *bytes_owned = memOwnedHash.lookup(&pid_tgid);

            if (!bytes_owned) {
                memFreeHash.delete(&pid_tgid);
                return 0;
            }

            if (*bytes_owned <= *byte_alloc) {
                memOwnedHash.delete(&pid_tgid);
                bpf_trace_printk("process %d now do not have any memory.", pid);
            } else {
                *bytes_owned -= *byte_alloc;
                memOwnedPairs.delete(&memAllocCall);
                memOwnedHash.update(&pid_tgid, bytes_owned);
                bpf_trace_printk("After Free, process %d now have %u bytes in memory", pid, *bytes_owned);
            }

            memFreeHash.delete(&pid_tgid);
        }
    }
    return 0;
};

struct dim3 {
    u64 x;
    u64 y;
    u64 z;
};

struct cudaStream_t {
    u64 dummy;
};

int cudaStreamIsCapturingEntry(struct pt_regs *ctx) {
    bpf_trace_printk("cudaStreamIsCapturing entered.");
    return 0;
};
int cudaStreamSynchronizeEntry(struct pt_regs *ctx) {
    bpf_trace_printk("cudaStreamSynchronize entered.");
    return 0;
};