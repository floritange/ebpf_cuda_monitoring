#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import psutil
import ctypes
import time


libcudart_list = [
    "/root/miniconda3/envs/tangou101/lib/python3.10/site-packages/torch/lib/../../nvidia/cuda_runtime/lib/libcudart.so.12",
    # "/root/miniconda3/lib/libcudart.so",
    # "/root/miniconda3/pkgs/cudatoolkit-11.8.0-h6a678d5_0/lib/libcudart.so",
    # "/usr/local/cuda-11.0/targets/x86_64-linux/lib/libcudart.so",
    "/usr/local/cuda-12.2/targets/x86_64-linux/lib/libcudart.so",
    "/usr/local/cuda-12.2/targets/x86_64-linux/lib/libcudart.so.12",
]
libcuda_list = [
    "/usr/lib64/libcuda.so.550.54.15",
    "/usr/lib64/libcuda.so.1",
]
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
    "cuInit": "cuInitEntry",
    "cuInit": "cuInitEntry",
}
uretprobe_mapping = {
    "cudaGetDevice": "cudaGetDeviceExited",
    "cudaGetLastError": "cudaGetLastErrorExited",
    "cudaLaunchKernel": "cudaLaunchKernelExited",
    "cudaFree": "cudaFreeExited",
    "cudaMalloc": "cudaMallocExited",
    "cudaMemcpyAsync": "cudaMemcpyAsyncExited",
    "cudaStreamIsCapturing": "cudaStreamIsCapturingExited",
    "cudaStreamSynchronize": "cudaStreamSynchronizeExited",
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
    # uprobe_attach_cuda(libcuda_list)


print("Tracing memMalloc()... Hit Ctrl-C to end.")

# cudaMallocLog_map = b.get_table("cudaMallocLog_map")
# 定义处理环形缓冲区事件的回调函数


try:
    while True:

        # # 遍历map并打印数据
        # for key, value in cudaMallocLog_map.items():
        #     print("Time Start: {}".format(value.timeStart))
        #     print("DevPtr: {}".format(hex(value.devPtr)))
        #     print("Size: {}".format(value.size))
        #     print("Value: {}".format(value.value))
        # 添加适当的延迟
        time.sleep(1)

except KeyboardInterrupt:
    pass
