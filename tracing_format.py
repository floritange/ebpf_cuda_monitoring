import json


# 读取日志文件
def read_log_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return lines


# 解析日志数据
def parse_log_line(line):
    parts = line.strip().split(", ")
    print(line)
    data = {}
    for part in parts:
        key, value = part.split(": ")
        if key in ["pid", "tid", "size", "ByteCount"]:
            data[key] = int(value)
        elif key in ["time_start", "time_end"]:
            data[key] = int(value)
        elif key in ["devPtr", "dstDevice", "srcDevice", "srcHost", "dstHost", "hStream", "f", "kernelParams", "extra"]:
            data[key] = int(value, 16)
    return data


# 创建Chrome Tracing事件
def create_trace_event(name, data):
    duration = (data["time_end"] - data["time_start"]) / 1000  # 将纳秒转换为微秒
    print(data)
    event = {
        "pid": data["pid"],
        "tid": data["tid"],
        "ts": data["time_start"] / 1000,  # 将纳秒转换为微秒
        "ph": "X",  # 完整事件
        "name": name,
        "dur": duration,
        "args": {
            k: (
                hex(v)
                if isinstance(v, int) and k != "pid" and k != "tid" and k != "time_start" and k != "time_end" and k != "size" and k != "ByteCount"
                else v
            )
            for k, v in data.items()
            if k not in ["pid", "tid", "time_start", "time_end"]
        },
    }
    return event


# 解析日志文件并生成Chrome Tracing事件
def process_log_file(file_path):
    lines = read_log_file(file_path)
    trace_events = []
    prefix_to_name = {
        "[cuMemAlloc_v2]": "cuMemAlloc_v2",
        "[cuMemcpyHtoDAsync_v2]": "cuMemcpyHtoDAsync_v2",
        "[cuStreamSynchronize]": "cuStreamSynchronize",
        "[cuLaunchKernel]": "cuLaunchKernel",
        "[cuMemcpyDtoHAsync_v2]": "cuMemcpyDtoHAsync_v2",
        "[cuMemFree_v2]": "cuMemFree_v2",
    }

    for line in lines:
        for prefix, name in prefix_to_name.items():
            if line.startswith(prefix):
                data = parse_log_line(line[len(prefix) + 1 :])
                trace_events.append(create_trace_event(name, data))
                break  # 找到匹配前缀后跳出循环，继续处理下一行

    return trace_events


# 将Chrome Tracing事件写入JSON文件
def write_trace_file(trace_events, output_path):
    trace = {"traceEvents": trace_events, "displayTimeUnit": "ns"}
    with open(output_path, "w") as f:
        json.dump(trace, f, indent=4)
    print(f"Trace written to {output_path}")


input_path = "logfile.txt"
output_path = "chrome_trace.json"
trace_events = process_log_file(input_path)
write_trace_file(trace_events, output_path)
