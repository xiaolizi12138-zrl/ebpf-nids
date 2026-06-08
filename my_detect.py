import os
import pickle
import numpy as np
import pandas as pd
import glob
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, f1_score, classification_report

# ===================== 配置 =====================
BASE_PATH = "./IDS_SAVE"
DATA_DIR = f"{BASE_PATH}/data"
MODEL_DIR = f"{BASE_PATH}/model"
REPORT_DIR = f"{BASE_PATH}/report"
DOCS_DIR = f"{BASE_PATH}/docs"
for d in [DATA_DIR, MODEL_DIR, REPORT_DIR, DOCS_DIR]:
    os.makedirs(d, exist_ok=True)

FULL_CSV = f"{DATA_DIR}/CICIDS2017_all.csv"       # 合并后的完整文件
SAMPLE_CSV = f"{DATA_DIR}/CICIDS2017_sampled.csv" # 采样后的训练文件
SAMPLE_SIZE = 300000  # 采样行数（30万）

# 正确的原始数据源（共享文件夹中的 MachineLearningCVE-2）
SOURCE_DIR = "/mnt/hgfs/MachineLearningCVE-2"

FEATURE_LIST = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'SYN Flag Count', 'ACK Flag Count'
]

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

# ===================== 步骤1：合并数据（低内存） =====================
def merge_data_without_full_load():
    print("===== 步骤1：合并原始CSV（低内存模式） =====")
    if not os.path.exists(SOURCE_DIR):
        print(f"错误：数据源目录不存在 -> {SOURCE_DIR}")
        return False

    csv_files = glob.glob(os.path.join(SOURCE_DIR, "*.csv"))
    if not csv_files:
        print(f"在 {SOURCE_DIR} 中没有找到 CSV 文件。")
        return False

    print(f"找到 {len(csv_files)} 个文件，开始合并...")
    first = True
    total_rows = 0
    for f in csv_files:
        print(f"  处理: {os.path.basename(f)}")
        chunk_iter = pd.read_csv(f, chunksize=50000, low_memory=False)
        for chunk in chunk_iter:
            if "Label" in chunk.columns:
                chunk["Label"] = chunk["Label"].astype(str).str.strip()
            chunk.to_csv(FULL_CSV, mode='a', index=False, header=first)
            first = False
            total_rows += len(chunk)
    print(f"合并完成！总行数: {total_rows}, 保存至: {FULL_CSV}")
    return total_rows

# ===================== 步骤2：蓄水池采样 =====================
def reservoir_sample():
    print(f"\n===== 步骤2：从完整数据中随机采样 {SAMPLE_SIZE} 行 =====")
    reservoir = []
    processed = 0
    chunk_size = 50000
    for chunk in pd.read_csv(FULL_CSV, chunksize=chunk_size, low_memory=False):
        if "Label" in chunk.columns:
            chunk["Label"] = chunk["Label"].astype(str).str.strip()
        for idx, row in chunk.iterrows():
            processed += 1
            if len(reservoir) < SAMPLE_SIZE:
                reservoir.append(row.to_dict())
            else:
                j = np.random.randint(0, processed)
                if j < SAMPLE_SIZE:
                    reservoir[j] = row.to_dict()
        del chunk
    sampled_df = pd.DataFrame(reservoir)
    sampled_df.to_csv(SAMPLE_CSV, index=False)
    print(f"采样完成，实际获得 {len(sampled_df)} 行，保存至: {SAMPLE_CSV}")
    
    print("\n采样数据标签分布（前15种）:")
    print(sampled_df["Label"].value_counts().head(15))
    return sampled_df

# ===================== 步骤3：训练模型（处理稀有类别） =====================
def train_model(df):
    print("\n===== 步骤3：训练随机森林多分类模型 =====")
    df = df[FEATURE_LIST + ["Label"]].copy().fillna(0)
    
    # 移除样本数少于2的类别
    label_counts = df["Label"].value_counts()
    rare_labels = label_counts[label_counts < 2].index.tolist()
    if rare_labels:
        print(f"移除稀有类别（样本数<2）: {rare_labels}")
        df = df[~df["Label"].isin(rare_labels)]
    
    y = df["Label"]
    X = df[FEATURE_LIST]
    print(f"训练数据形状: {X.shape}, 标签类别数: {y.nunique()}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    y_test_bin = (y_test != "BENIGN").astype(int)
    y_pred_bin = (y_pred != "BENIGN").astype(int)
    rec = recall_score(y_test_bin, y_pred_bin)
    f1 = f1_score(y_test_bin, y_pred_bin)
    
    print(f"\n模型评估：")
    print(f"  多分类准确率: {acc:.4f}")
    print(f"  二分类召回率: {rec:.4f}")
    print(f"  二分类 F1: {f1:.4f}")
    
    # 保存模型
    with open(f"{MODEL_DIR}/rf_base.pkl", "wb") as f:
        pickle.dump(rf, f)
    print(f"模型已保存: {MODEL_DIR}/rf_base.pkl")
    
    # 轻量化模型
    rf_light = RandomForestClassifier(n_estimators=25, random_state=42, n_jobs=-1)
    rf_light.fit(X_train, y_train)
    with open(f"{MODEL_DIR}/rf_light.pkl", "wb") as f:
        pickle.dump(rf_light, f)
    print(f"轻量化模型已保存: {MODEL_DIR}/rf_light.pkl")
    
    return rf

# ===================== 步骤4：验证模型 =====================
def verify_model(model):
    print("\n===== 步骤4：验证模型是否学会检测攻击 =====")
    ddos_feat = [500, 3000, 2800, 500000, 480000, 300, 80, 280, 70, 4000000, 50000, 100, 90, 10, 2000]
    pred = model.predict([ddos_feat])[0]
    print(f"DDoS 样本预测: {pred}")
    if pred != "BENIGN":
        print("✓ 成功！模型能够识别攻击流量。")
    else:
        print("✗ 失败：模型仍输出 BENIGN，请检查数据或增加采样量。")
    return pred

# ===================== 主程序 =====================
if __name__ == "__main__":
    # 如果已经合并和采样过，可以跳过前两步，直接加载采样数据
    if os.path.exists(SAMPLE_CSV):
        print("发现已存在的采样文件，直接加载...")
        sampled_df = pd.read_csv(SAMPLE_CSV)
        if "Label" in sampled_df.columns:
            sampled_df["Label"] = sampled_df["Label"].astype(str).str.strip()
        print(f"加载采样数据，共 {len(sampled_df)} 行")
    else:
        total = merge_data_without_full_load()
        if not total:
            exit(1)
        sampled_df = reservoir_sample()
    
    model = train_model(sampled_df)
    verify_model(model)
    
    print("\n===== 全部完成 =====")
    print("新模型已生成，可以用于入侵检测（支持攻击类型识别）。")
基于训练数据中少量 Web 攻击样本，自动提取其 15 维网络流特征，并计算每个特征的 5% 与 95% 分位数作为正常 Web 攻击的分布区间（同时预留 10% 的容差）。在实时检测时，先让原始随机森林模型预测，仅当模型判定为正常（BENIGN）时，才检查当前流量的特征是否全部落在该区间内；若全部符合，则强制修正为 Web 攻击，否则保留原正常结果。这种后处理规则不修改原模型，通过特征分布的统计规律弥补了小样本下模型难以学习 Web 攻击模式的缺陷，从而显著提升检出率。
import os
import pickle
import numpy as np
import pandas as pd
import glob

# ===================== 路径配置（请根据实际情况修改文件名） =====================
DATA_FILE = "./IDS_SAVE/data/CICIDS2017_sampled.csv"
MODEL_FILE = "./IDS_SAVE/model/rf_final.pkl"

# 如果指定模型不存在，自动查找第一个 .pkl
if not os.path.exists(MODEL_FILE):
    pkl_files = glob.glob("./IDS_SAVE/model/*.pkl")
    if pkl_files:
        MODEL_FILE = pkl_files[0]
        print(f"自动使用模型文件: {MODEL_FILE}")
    else:
        raise FileNotFoundError("未找到任何 .pkl 模型文件")

FEATURE_LIST = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'SYN Flag Count', 'ACK Flag Count'
]

# ===================== 自动探测 Web 标签 =====================
def get_web_labels(data_path):
    """从数据中读取所有包含 'Web' 的标签（不区分大小写）"""
    print("正在探测数据中的 Web 攻击标签...")
    web_labels_set = set()
    # 分块读取，避免内存过大
    for chunk in pd.read_csv(data_path, chunksize=50000, low_memory=False):
        if "Label" not in chunk.columns:
            continue
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        # 查找包含 'web' 的标签（忽略大小写）
        mask = chunk["Label"].str.contains('web', case=False, na=False)
        if mask.any():
            labels = chunk.loc[mask, "Label"].unique()
            web_labels_set.update(labels)
    web_labels = list(web_labels_set)
    if not web_labels:
        raise ValueError("未找到任何包含 'Web' 的标签，请检查数据文件是否正确。")
    print(f"探测到 {len(web_labels)} 个 Web 攻击标签:")
    for lbl in web_labels:
        print(f"  {repr(lbl)}")
    return web_labels

# ===================== 学习规则 =====================
def learn_web_rules(data_path, web_labels):
    print(f"正在从 {data_path} 中提取 Web 攻击样本...")
    web_samples = []
    chunk_size = 50000
    for chunk in pd.read_csv(data_path, chunksize=chunk_size, low_memory=False):
        if "Label" not in chunk.columns:
            continue
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        mask = chunk["Label"].isin(web_labels)
        if mask.any():
            web_chunk = chunk.loc[mask, FEATURE_LIST]
            web_samples.append(web_chunk)
    if not web_samples:
        raise ValueError("未提取到任何 Web 攻击样本，无法学习规则。")
    web_df = pd.concat(web_samples, ignore_index=True)
    print(f"成功提取 {len(web_df)} 条 Web 攻击样本")
    # 计算每个特征的 5% 和 95% 分位数作为规则区间
    rules = {}
    for col in FEATURE_LIST:
        low = web_df[col].quantile(0.05)
        high = web_df[col].quantile(0.95)
        rules[col] = (low, high)
    return rules

def is_web_attack(features, rules, tolerance=0.1):
    for i, col in enumerate(FEATURE_LIST):
        low, high = rules[col]
        val = features[i]
        if not (low * (1 - tolerance) <= val <= high * (1 + tolerance)):
            return False
    return True

def create_enhanced_predictor(model_path, rules, tolerance=0.1):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    def enhanced_predict(features):
        raw_pred = model.predict([features])[0]
        if raw_pred != "BENIGN":
            return raw_pred, False
        if is_web_attack(features, rules, tolerance):
            return "Web Attack (Rule)", True
        return "BENIGN", False
    return enhanced_predict

# ===================== 主程序 =====================
if __name__ == "__main__":
    print("===== Web 攻击增强模块（完全自动版）=====")
    try:
        # 1. 探测 Web 标签
        web_labels = get_web_labels(DATA_FILE)
        # 2. 学习规则
        rules = learn_web_rules(DATA_FILE, web_labels)
    except Exception as e:
        print(f"错误: {e}")
        print("请检查数据文件路径是否正确，以及文件中是否包含 Web 攻击样本。")
        exit(1)

    print("\n特征规则（5%~95% 分位数）：")
    for col, (low, high) in rules.items():
        print(f"  {col:30s}: [{low:.2f}, {high:.2f}]")

    # 3. 创建增强预测器
    predictor = create_enhanced_predictor(MODEL_FILE, rules, tolerance=0.1)

    # 4. 从数据中取一条真实 Web 攻击样本进行测试
    print("\n----- 真实 Web 攻击样本测试 -----")
    # 重新读取数据找到第一条 Web 攻击样本
    found = False
    for chunk in pd.read_csv(DATA_FILE, chunksize=50000):
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        mask = chunk["Label"].isin(web_labels)
        if mask.any():
            sample = chunk[mask].iloc[0]
            features = sample[FEATURE_LIST].tolist()
            true_label = sample["Label"]
            found = True
            break
    if found:
        with open(MODEL_FILE, "rb") as f:
            base_model = pickle.load(f)
        raw_pred = base_model.predict([features])[0]
        enhanced_pred, corrected = predictor(features)
        print(f"真实标签: {true_label}")
        print(f"原始模型预测: {raw_pred}")
        print(f"增强后预测: {enhanced_pred} (是否修正: {corrected})")
    else:
        print("未找到 Web 攻击样本，无法进行真实测试。")

    # 5. 自定义样本测试（模拟 Web 攻击）
    print("\n----- 自定义样本测试 -----")
    test_samples = {
        "正常流量": [12000, 8, 6, 500, 300, 100, 40, 90, 30, 8000, 70, 1500, 1400, 2, 10],
        "DDoS攻击": [500, 3000, 2800, 500000, 480000, 300, 80, 280, 70, 4000000, 50000, 100, 90, 10, 2000],
        "SSH暴力破解": [200000, 80, 75, 4000, 3800, 60, 20, 55, 18, 12000, 45, 5000, 4900, 100, 30],
        "模拟Web攻击": [35000, 45, 40, 2200, 1800, 180, 25, 160, 22, 35000, 210, 950, 880, 8, 22],
    }
    for name, feat in test_samples.items():
        pred, corrected = predictor(feat)
        print(f"{name:12s} -> 预测: {pred:20s} (修正: {corrected})")

    print("\n===== 增强模块已就绪 =====")
    print("提示：可以将此模块集成到您的检测流程中，替换原有 model.predict 调用。")