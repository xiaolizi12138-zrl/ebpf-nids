# ============================================================
#  eBPF 网络攻击检测系统 - 后端 API 服务
#  Flask + SocketIO + SQLite
# ============================================================

FROM python:3.11-slim

WORKDIR /app

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制后端代码
COPY . .

# 暴露端口
EXPOSE 5000

# 启动后端服务
CMD ["python", "app.py"]
