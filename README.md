```bash
# bcc环境
python cudaProfiler.py
# pytorch环境
python test.py
# 输出结果在logfile.txt，格式化为chrome://tracing/。结果为chrome_trace.json
python tracing_format.py
```
可视化图片
![example](./chrome_trace.png)