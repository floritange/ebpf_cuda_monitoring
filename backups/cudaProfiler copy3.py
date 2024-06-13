#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import psutil
import ctypes
import time


libcuda_list = [
    "/root/miniconda3/envs/tangou101/lib/python3.10/site-packages/torch/lib/../../nvidia/cuda_runtime/lib/libcudart.so.12",
    "/lib64/libcuda.so.1",
]

cfile_path = "cudaProfiler.c"
with open(cfile_path, "r") as file:
    cfile_content = file.read()
# load BPF program
b = BPF(text=cfile_content)

uprobe_mapping = {
    "cudaLaunchKernel": "cudaLaunchKernelEntry",
    "cudaFree": "cudaFreeEntry",
    "cudaMalloc": "cudaMallocEntry",
    "cudaMemcpyAsync": "cudaMemcpyAsyncEntry",
    "cudaStreamSynchronize": "cudaStreamSynchronizeEntry",
    "cuLaunchKernel": "cuLaunchKernelEntry",
    "cuMemFree_v2": "cuMemFree_v2Entry",
    "cuMemAlloc_v2": "cuMemAlloc_v2Entry",
    "cuStreamSynchronize": "cuStreamSynchronizeEntry",
}
uretprobe_mapping = {
    "cudaLaunchKernel": "cudaLaunchKernelExited",
    "cudaFree": "cudaFreeExited",
    "cudaMalloc": "cudaMallocExited",
    "cudaMemcpyAsync": "cudaMemcpyAsyncExited",
    "cudaStreamSynchronize": "cudaStreamSynchronizeExited",
    "cuMemcpyHtoDAsync_v2": "cuMemcpyHtoDAsync_v2Entry",
}


def handle_event(ctx, data, size):
    cudaMallocLogRing = ctypes.cast(data, ctypes.POINTER(cudaMallocLog_t)).contents
    print(f"size:{cudaMallocLogRing.size}")


def uprobe_attach_cuda(path_to_attach: str):
    for sym, fn_name in uprobe_mapping.items():
        try:
            b.attach_uprobe(name=path_to_attach, sym=sym, fn_name=fn_name)
        except Exception as e:
            print("uprobe_attach_cuda", e)
            continue
    for sym, fn_name in uretprobe_mapping.items():
        try:
            b.attach_uretprobe(name=path_to_attach, sym=sym, fn_name=fn_name)
        except Exception as e:
            continue


for libcudart_path in libcuda_list:
    uprobe_attach_cuda(libcudart_path)


print("Tracing cuda... Hit Ctrl-C to end.")

# cudaMallocLog_map = b.get_table("cudaMallocLog_map")
# 定义处理环形缓冲区事件的回调函数

try:
    while True:
        # 添加适当的延迟
        time.sleep(1)

except KeyboardInterrupt:
    pass
