# ebpf Profiling CUDA Runtime/Driver libs
A kernel-level GPU event tracing system uses eBPF to capture CUDA runtime behaviors (memory management, kernel launches, data transfers, synchronization), enabling performance optimization for DNN/LLM training and inference. 

#### EN
```bash
#### env #####
# bcc
python cudaProfiler.py
# pytorch
python test.py
# output: logfile.txt，result: chrome_trace.json. chrome searching to visualize: chrome://tracing/。
python tracing_format.py
# auto process file logfile.txt，timing fresh to get Figure，result is trace_mem.png
python trace_mem.py
```

可视化图片
![chrome_trace](./patent/chrome_trace.png)
trace_memory
![trace_mem](./trace_mem.png)

#### CN
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

# 📚 Reference
```bibtex
@patent{CN202410942419.2,
    author = "Chen Pengfei; Tan Gou; Zhong Yuan; Zhang Chuanfu; Zheng Zibin",
    title = "Lightweight and Non-intrusive GPU Behavior Observation Method, Device, Equipment and Storage Medium",
    number = "CN202410942419.2",
    year = "2024",
    month = "07",
    note = "Application Date: 2024.07.15; Applicant: Sun Yat-sen University; Applicant's Country/Region: CN; Agent: Shi Qinwen; Agency: Beijing Jijia Intellectual Property Agency Co., Ltd. 11227; Publication Number: CN118567952A; Publication Date: 2024.08.30; IPC Classification: G06F11/30;G06F11/32; CPC Invention: G06F11/3024;G06F11/3089;G06F11/323",
}
```

```bibtex
@patent{CN202410942419.2,
    author = "陈鹏飞; 谭苟; 钟源; 张传富; 郑子彬",
    title = "轻量无侵入GPU行为观测方法、装置、设备及存储介质",
    number = "CN202410942419.2",
    year = "2024",
    month = "07",
    note = "申请日：2024.07.15; 申请人：中山大学; 申请人所在国家/地区：CN; 代理人：石钦文; 代理机构：北京集佳知识产权代理有限公司 11227; 公开号：CN118567952A; 公开日期：2024.08.30; IPC分类：G06F11/30;G06F11/32; CPC发明：G06F11/3024;G06F11/3089;G06F11/323",
}
```
