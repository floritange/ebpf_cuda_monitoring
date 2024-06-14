#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep
import psutil
import ctypes
import time


libcuda_list = [
    "/lib64/libcuda.so.1",
]

cfile_path = "cudaProfiler.c"
with open(cfile_path, "r") as file:
    cfile_content = file.read()
# load BPF program
b = BPF(text=cfile_content)

uprobe_mapping = {
    "cuMemAlloc_v2": "cuMemAlloc_v2Entry",
    # "cuLaunchKernel": "cuLaunchKernelEntry",
    # "cuMemFree_v2": "cuMemFree_v2Entry",
    # "cuMemcpyHtoDAsync_v2": "cuMemcpyHtoDAsync_v2Entry",
    # "cuMemcpyDtoHAsync_v2": "cuMemcpyDtoHAsync_v2Entry",
    # "cuStreamSynchronize": "cuStreamSynchronizeEntry",
}
uretprobe_mapping = {
    "cuMemAlloc_v2": "cuMemAlloc_v2Exited",
    # "cuLaunchKernel": "cuLaunchKernelExited",
    # "cuMemFree_v2": "cuMemFree_v2Exited",
    # "cuMemcpyHtoDAsync_v2": "cuMemcpyHtoDAsync_v2Exited",
    # "cuMemcpyDtoHAsync_v2": "cuMemcpyDtoHAsync_v2Exited",
    # "cuStreamSynchronize": "cuStreamSynchronizeExited",
}


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


for libcudart_path in libcuda_list:
    uprobe_attach_cuda(libcudart_path)


print("Tracing cuda... Hit Ctrl-C to end.")


class CuMemAlloc_v2Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("devPtrPtr", ctypes.c_void_p),
        ("devPtr", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
    ]


# 回调函数
def print_cuMemAlloc_v2_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuMemAlloc_v2Data)).contents
    print(
        f"[cuMemAlloc_v2] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, devPtr: {hex(event.devPtr)}, size: {event.size}"
    )


# 设置ring buffer回调
b["cuMemAlloc_v2_events"].open_ring_buffer(print_cuMemAlloc_v2_event)

try:
    while True:
        b.ring_buffer_poll()
        # 添加适当的延迟
        time.sleep(1)

except KeyboardInterrupt:
    pass
