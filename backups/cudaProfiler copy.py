#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import psutil

libcudart_list = [
    "/root/miniconda3/envs/tangou101/lib/python3.10/site-packages/nvidia/cuda_runtime/lib/libcudart.so.12",
    # "/root/miniconda3/lib/libcudart.so",
    # "/root/miniconda3/pkgs/cudatoolkit-11.8.0-h6a678d5_0/lib/libcudart.so",
    # "/usr/local/cuda-11.0/targets/x86_64-linux/lib/libcudart.so",
    "/usr/local/cuda-12.2/targets/x86_64-linux/lib/libcudart.so",
    "/usr/local/cuda-12.2/targets/x86_64-linux/lib/libcudart.so.12",
]
libcuda_list = ["/usr/lib/libcuda.so"]
cfile_path = "cudaProfiler.c"
with open(cfile_path, "r") as file:
    cfile_content = file.read()
# load BPF program
b = BPF(text=cfile_content)

uprobe_mapping = {
    "cudaGetDevice": "cudaGetDeviceEntry",
    "cudaGetLastError": "cudaGetLastErrorEntry",
    "cudaLaunchKernel": "cudaLaunchKernelEntry",
    "cudaFree": "cudaFreeEntry",
    "cudaMalloc": "cudaMallocEntry",
    "cudaMemcpyAsync": "cudaMemcpyAsyncEntry",
    "cudaStreamIsCapturing": "cudaStreamIsCapturingEntry",
    "cudaStreamSynchronize": "cudaStreamSynchronizeEntry",
}
uretprobe_mapping = {
    "cudaGetDevice": "cudaGetDeviceExited",
    "cudaGetLastError": "cudaGetLastErrorExited",
    "cudaLaunchKernel": "cudaLaunchKernelExited",
    "cudaFree": "cudaFreeExited",
    "cudaMalloc": "cudaMallocExited",
    "cudaMemcpy": "cudaMemcpyExited",
}
uprobeCu_mapping = {
    "cuMemAlloc": "cudaMallocEntry",
}

# 获取当前运行的进程列表
current_processes = psutil.process_iter(["pid", "name"])

# 将当前进程的PID存储在集合中
current_pids = set([process.info["pid"] for process in current_processes])


def uprobe_attach_cuda(path_to_attach: str):
    for sym, fn_name in uprobe_mapping.items():
        try:
            b.attach_uprobe(name=path_to_attach, sym=sym, fn_name=fn_name)
        except Exception as e:
            continue
    for sym, fn_name in uretprobe_mapping.items():
        try:
            b.attach_uretprobe(name=path_to_attach, sym=sym, fn_name=fn_name)
        except Exception as e:
            continue


for libcudart_path in libcudart_list:
    uprobe_attach_cuda(libcudart_path)


# Process the received data
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("Received data - timestamp: %d, devPtr: %s, size: %d, value: %d" % (event.timestamp, hex(event.devPtr), event.size, event.value))


# Attach the processing function to the BPF perf buffer
b["events"].open_perf_buffer(print_event)

# Keep the program running
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass
