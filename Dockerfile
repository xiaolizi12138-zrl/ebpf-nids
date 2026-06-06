# ============================================================
#  eBPF 网络攻击检测系统 - Dashboard 前端
#  基于 Nginx 的静态页面托管
# ============================================================
#  使用方式：
#    构建：docker build -t ebpf-dashboard .
#    运行：docker run -d -p 8080:80 --name dashboard ebpf-dashboard
#    访问：http://localhost:8080
# ============================================================

# 使用轻量级 Nginx Alpine 镜像（约 23MB）
FROM nginx:alpine

# 设置工作目录
WORKDIR /usr/share/nginx/html

# 复制 Dashboard 静态页面
COPY dashboard.html ./index.html

# 复制 Nginx 配置文件（含反向代理配置）
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 暴露 80 端口
EXPOSE 80

# 前台启动 Nginx（保持容器运行）
CMD ["nginx", "-g", "daemon off;"]
