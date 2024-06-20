import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import subprocess
import matplotlib.dates as mdates
import time


# 读取系统启动时间
def get_system_start_time():
    result = subprocess.run(["uptime", "-s"], stdout=subprocess.PIPE)
    start_time_str = result.stdout.decode().strip()
    start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
    return start_time


# 读取日志文件
def read_log_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return lines


# 解析日志数据
def parse_log_line(line):
    parts = line.strip().split(", ")
    data = {}
    for part in parts:
        key_value = part.split(": ")
        if len(key_value) == 2:
            key, value = key_value
            if key in ["pid", "tid", "size", "ByteCount"]:
                data[key] = int(value)
            elif key in ["time_start", "time_end"]:
                data[key] = int(value)
            elif key in ["devPtr", "dstDevice", "srcDevice", "srcHost", "dstHost", "hStream", "f", "kernelParams", "extra"]:
                data[key] = int(value, 16)
    return data


# 将ebpf时间戳转换为实际时间
def convert_to_actual_time(timestamp_ns, system_start_time):
    timestamp_s = timestamp_ns / 1e9
    actual_time = system_start_time + timedelta(seconds=timestamp_s)
    return actual_time


# 解析日志文件并提取cuMemAlloc_v2和cuMemFree_v2事件
def extract_memory_events(file_path, system_start_time):
    lines = read_log_file(file_path)
    alloc_events = []
    free_events = []
    prefix_to_name = {
        "[cuMemAlloc_v2]": "cuMemAlloc_v2",
        "[cuMemFree_v2]": "cuMemFree_v2",
    }

    for line in lines:
        content = line.split(" - ", 1)[1].strip()
        for prefix, name in prefix_to_name.items():
            if content.startswith(prefix):
                data = parse_log_line(content[len(prefix) :].strip())
                data["log_time"] = convert_to_actual_time(data["time_start"], system_start_time)
                if name == "cuMemAlloc_v2":
                    alloc_events.append(data)
                elif name == "cuMemFree_v2":
                    free_events.append(data)
                break  # 找到匹配前缀后跳出循环，继续处理下一行

    return alloc_events, free_events


# 生成显存使用随时间变化的图
def plot_memory_usage(alloc_events, free_events, system_start_time):
    time_points = []
    memory_usage = []
    memory_map = {}

    for event in alloc_events:
        time_points.append(convert_to_actual_time(event["time_start"], system_start_time))
        memory_map[event["devPtr"]] = event["size"]
        memory_usage.append(sum(memory_map.values()) / (1024 * 1024))  # 转换为MB

    for event in free_events:
        if event["devPtr"] in memory_map:
            time_points.append(convert_to_actual_time(event["time_start"], system_start_time))
            memory_map.pop(event["devPtr"], None)
            memory_usage.append(sum(memory_map.values()) / (1024 * 1024))  # 转换为MB

    # 绘制图形
    plt.figure(figsize=(10, 5))
    plt.plot(time_points, memory_usage, marker="o")
    plt.xlabel("Time")
    plt.ylabel("Memory Usage (MB)")
    plt.title("GPU Memory Usage Over Time")
    plt.grid(True)
    # 设置日期格式
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())

    plt.xticks(rotation=45)
    plt.tight_layout()  # 自动调整布局
    plt.show()
    plt.savefig("trace_mem.png")


# 定期刷新绘图
def refresh_plot(interval, input_path, system_start_time):
    while True:
        alloc_events, free_events = extract_memory_events(input_path, system_start_time)
        plot_memory_usage(alloc_events, free_events, system_start_time)
        time.sleep(interval)


# 输入路径
input_path = "logfile.txt"

# 获取系统启动时间
system_start_time = get_system_start_time()

# 定期刷新间隔（秒）
interval = 60  # 每60秒刷新一次

# 开始定期刷新绘图
refresh_plot(interval, input_path, system_start_time)
