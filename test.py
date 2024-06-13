import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import time
import datetime
import multiprocessing

# 检查CUDA是否可用
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 定义数据的维度
data_dim = 10000
batch_size = 1280

# 定义模型的维度
input_dim = data_dim
hidden_dim = 5
output_dim = 2

# 定义一个简单的神经网络模型并将其转移到CUDA上
class SimpleNN(nn.Module):
    def __init__(self):
        super(SimpleNN, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return x

while True:
    # 生成随机输入数据（示例中使用随机数据代替真实数据）
    input_data = torch.randn(batch_size, data_dim).to(device)
    # 加载模型
    model = SimpleNN().to(device)
    model.eval()  # 将模型设置为评估模式
    # 进行推理
    output = model(input_data)
    # break

    # 输出结果和时间
    out_time = datetime.datetime.fromtimestamp(time.time()).strftime("%H:%M:%S")
    print(f"time: {out_time}, output: {len(output)}")
    time.sleep(2)
    # 释放GPU资源
    del input_data
    del output
    del model
    torch.cuda.empty_cache()
    time.sleep(2)
    break
    
    # torch.cuda.empty_cache()
    # time.sleep(3)
    # # 生成随机输入数据（示例中使用随机数据代替真实数据）
    # input_data = torch.randn(batch_size, data_dim).to(device)
    # # 加载模型
    # model = SimpleNN().to(device)
    # model.eval()  # 将模型设置为评估模式
    # # 进行推理
    # output = model(input_data)
    # # 输出结果和时间
    # out_time = datetime.datetime.fromtimestamp(time.time()).strftime("%H:%M:%S")
    # print(f"time: {out_time}, output: {len(output)}")
    # time.sleep(3)
    # # 释放GPU资源
    # del input_data
    # del output
    # del model
    # torch.cuda.empty_cache()
    # time.sleep(3)
    # break

