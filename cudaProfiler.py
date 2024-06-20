#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep
import ctypes
import time
import atexit
import logging

logging.basicConfig(filename="./logfile.txt", level=logging.INFO, format="%(asctime)s - %(message)s")
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
    "cuLaunchKernel": "cuLaunchKernelEntry",
    "cuMemFree_v2": "cuMemFree_v2Entry",
    "cuMemcpyHtoDAsync_v2": "cuMemcpyHtoDAsync_v2Entry",
    "cuMemcpyDtoHAsync_v2": "cuMemcpyDtoHAsync_v2Entry",
    "cuStreamSynchronize": "cuStreamSynchronizeEntry",
}
uretprobe_mapping = {
    "cuMemAlloc_v2": "cuMemAlloc_v2Exited",
    "cuLaunchKernel": "cuLaunchKernelExited",
    "cuMemFree_v2": "cuMemFree_v2Exited",
    "cuMemcpyHtoDAsync_v2": "cuMemcpyHtoDAsync_v2Exited",
    "cuMemcpyDtoHAsync_v2": "cuMemcpyDtoHAsync_v2Exited",
    "cuStreamSynchronize": "cuStreamSynchronizeExited",
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


######### cuMemAlloc_v2 #########
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
    log_info = f"[cuMemAlloc_v2] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, devPtr: {hex(event.devPtr)}, size: {event.size}"
    logging.info(log_info)


# 设置ring buffer回调
b["cuMemAlloc_v2_events"].open_ring_buffer(print_cuMemAlloc_v2_event)


######### cuLaunchKernel #########
class CuLaunchKernelData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("f", ctypes.c_ulonglong),
        ("gridDimX", ctypes.c_uint),
        ("gridDimY", ctypes.c_uint),
        ("gridDimZ", ctypes.c_uint),
        ("blockDimX", ctypes.c_uint),
        ("blockDimY", ctypes.c_uint),
        ("blockDimZ", ctypes.c_uint),
        ("sharedMemBytes", ctypes.c_uint),
        ("hStream", ctypes.c_ulonglong),
        ("kernelParams", ctypes.c_ulonglong),
        ("extra", ctypes.c_ulonglong),
    ]


def print_cuLaunchKernel_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuLaunchKernelData)).contents
    log_info = f"[cuLaunchKernel] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, f: {hex(event.f)}, gridDimX: {event.gridDimX}, gridDimY: {event.gridDimY}, gridDimZ: {event.gridDimZ}, blockDimX: {event.blockDimX}, blockDimY: {event.blockDimY}, blockDimZ: {event.blockDimZ}, sharedMemBytes: {event.sharedMemBytes}, hStream: {event.hStream}, kernelParams: {hex(event.kernelParams)}, extra: {hex(event.extra)}"
    logging.info(log_info)


b["cuLaunchKernel_events"].open_ring_buffer(print_cuLaunchKernel_event)


######### cuMemFree_v2 #########
class CuMemFree_v2Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("devPtr", ctypes.c_void_p),
    ]


def print_cuMemFree_v2_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuMemFree_v2Data)).contents
    dev_ptr_str = hex(event.devPtr) if event.devPtr else "None"
    log_info = f"[cuMemFree_v2] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, devPtr: {dev_ptr_str}"
    logging.info(log_info)


# 设置 ring buffer 回调
b["cuMemFree_v2_events"].open_ring_buffer(print_cuMemFree_v2_event)


######### cuMemcpyHtoDAsync_v2 #########
class CuMemcpyHtoDAsync_v2Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("dstDevice", ctypes.c_void_p),
        ("srcHost", ctypes.c_void_p),
        ("ByteCount", ctypes.c_size_t),
        ("hStream", ctypes.c_ulonglong),
    ]


def print_cuMemcpyHtoDAsync_v2_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuMemcpyHtoDAsync_v2Data)).contents
    log_info = f"[cuMemcpyHtoDAsync_v2] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, dstDevice: {hex(event.dstDevice)}, srcHost: {hex(event.srcHost)}, ByteCount: {event.ByteCount}, hStream: {event.hStream}"
    logging.info(log_info)


b["cuMemcpyHtoDAsync_v2_events"].open_ring_buffer(print_cuMemcpyHtoDAsync_v2_event)


######### cuMemcpyDtoHAsync_v2 #########
class CuMemcpyDtoHAsync_v2Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("dstHost", ctypes.c_void_p),
        ("srcDevice", ctypes.c_void_p),
        ("ByteCount", ctypes.c_size_t),
        ("hStream", ctypes.c_ulonglong),
    ]


def print_cuMemcpyDtoHAsync_v2_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuMemcpyDtoHAsync_v2Data)).contents
    log_info = f"[cuMemcpyDtoHAsync_v2] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, dstHost: {hex(event.dstHost)}, srcDevice: {hex(event.srcDevice)}, ByteCount: {event.ByteCount}, hStream: {event.hStream}"
    logging.info(log_info)


b["cuMemcpyDtoHAsync_v2_events"].open_ring_buffer(print_cuMemcpyDtoHAsync_v2_event)


######### cuStreamSynchronize #########
class CuStreamSynchronizeData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("time_start", ctypes.c_ulonglong),
        ("time_end", ctypes.c_ulonglong),
        ("hStream", ctypes.c_ulonglong),
    ]


def print_cuStreamSynchronize_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(CuStreamSynchronizeData)).contents
    log_info = f"[cuStreamSynchronize] pid: {event.pid}, tid: {event.tid}, time_start: {event.time_start}, time_end: {event.time_end}, hStream: {event.hStream}"
    logging.info(log_info)


b["cuStreamSynchronize_events"].open_ring_buffer(print_cuStreamSynchronize_event)


try:
    while True:
        b.ring_buffer_poll()
        # 添加适当的延迟
        time.sleep(1)

except KeyboardInterrupt:
    pass
