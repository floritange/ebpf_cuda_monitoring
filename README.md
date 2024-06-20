```bash
# bcc环境
python cudaProfiler.py
# pytorch环境
python test.py
# 输出结果在logfile.txt，格式化为chrome://tracing/。结果为chrome_trace.json
python tracing_format.py
# 自动处理logfile.txt，定期刷新画图，结果为trace_mem.png
python trace_mem.py
```

可视化图片
![chrome_trace](./patent/chrome_trace.png)
trace_memory
![trace_mem](./trace_mem.png)