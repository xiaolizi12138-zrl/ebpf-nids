import pickle
import pandas as pd

ATTACK_MAP = {
    "BENIGN": "正常流量",
    "DoS": "DoS拒绝服务攻击",
    "DDoS": "DDoS分布式洪水攻击",
    "FTP-Patator": "FTP暴力破解",
    "SSH-Patator": "SSH远程爆破",
    "WebAttack": "Web注入/XSS攻击",
    "Bot": "僵尸网络肉鸡流量",
    "Infiltration": "内网渗透攻击"
}

FEATURE_LIST = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'SYN Flag Count', 'ACK Flag Count'
]

with open("rf_final.pkl", "rb") as f:
    model = pickle.load(f)

def predict(features: list) -> int:
    """
    输入：15个特征的列表，顺序见 FEATURE_LIST
    输出：0 表示正常，1 表示攻击
    """
    df = pd.DataFrame([features], columns=FEATURE_LIST)
    raw_pred = model.predict(df)[0]
    return 0 if raw_pred == "BENIGN" else 1

if __name__ == "__main__":
    test_feat = [12000, 8, 6, 500, 300, 100, 40, 90, 30, 8000, 70, 1500, 1400, 2, 10]
    print(predict(test_feat))
