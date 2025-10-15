import time
import logging
import logging.handlers
import numpy as np
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, conf, rdpcap, wrpcap
import pandas as pd
import joblib
from datetime import datetime
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import winreg
import psutil
import queue
from concurrent.futures import ThreadPoolExecutor
import socket
import subprocess
from binascii import hexlify
import ipaddress
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import matplotlib
matplotlib.rcParams['font.family'] = 'Noto Sans TC'
matplotlib.rcParams['font.sans-serif'] = ['Noto Sans TC']
matplotlib.rcParams['axes.unicode_minus'] = False

# 確保日誌目錄存在
LOG_DIR = 'C:/IDS_defense/logs'
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(__name__)
    logger.debug(f"日誌目錄已創建或存在：{LOG_DIR}")
except Exception as e:
    print(f"無法創建日誌目錄 {LOG_DIR}：{str(e)}")
    logger = logging.getLogger(__name__)
    logger.warning(f"無法創建日誌目錄 {LOG_DIR}：{str(e)}，改用控制台日誌")

# 配置主日誌
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(LOG_DIR, 'realtime_detection.log')),
            logging.StreamHandler()
        ]
    )
    logger.debug("主日誌配置成功")
except Exception as e:
    logger.error(f"無法配置主日誌：{str(e)}")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

# 配置危險日誌
hazard_log_file = os.path.join(LOG_DIR, f'hazard_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
hazard_logger = logging.getLogger('HazardLogger')
hazard_logger.setLevel(logging.WARNING)
try:
    hazard_handler = logging.handlers.RotatingFileHandler(
        hazard_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    hazard_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    hazard_logger.addHandler(hazard_handler)
    logger.debug(f"危險日誌已配置：{hazard_log_file}")
except Exception as e:
    logger.error(f"無法配置危險日誌：{str(e)}")
    hazard_logger.addHandler(logging.StreamHandler())

# 配置封鎖日誌
block_log_file = os.path.join(LOG_DIR, f'block_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
block_logger = logging.getLogger('BlockLogger')
block_logger.setLevel(logging.INFO)
try:
    block_handler = logging.handlers.RotatingFileHandler(
        block_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    block_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    block_logger.addHandler(block_handler)
    logger.debug(f"封鎖日誌已配置：{block_log_file}")
except Exception as e:
    logger.error(f"無法配置封鎖日誌：{str(e)}")
    block_logger.addHandler(logging.StreamHandler())

# JSON 配置文件
CONFIG_FILE = 'C:/IDS_defense/config.json'

# 執行緒鎖
lock = threading.Lock()

# 封包處理隊列
packet_queue = queue.Queue()

def save_config(whitelist_ips, max_threads=4, monitor_mode='local', remote_ip=None, pcap_file=None):
    """保存白名單、最大執行緒數、監控模式、遠端 IP 和 pcap 檔案到 JSON 檔案"""
    try:
        config = {
            'whitelist_ips': whitelist_ips,
            'max_threads': max_threads,
            'monitor_mode': monitor_mode,
            'remote_ip': remote_ip,
            'pcap_file': pcap_file
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        logger.debug(f"已保存配置：白名單={whitelist_ips}, 最大執行緒數={max_threads}, 監控模式={monitor_mode}, 遠端IP={remote_ip}, pcap檔案={pcap_file}")
    except Exception as e:
        logger.error(f"無法保存配置：{str(e)}")

def load_config():
    """從 JSON 檔案載入白名單、最大執行緒數、監控模式、遠端 IP 和 pcap 檔案"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return (
                    config.get('whitelist_ips', []),
                    config.get('max_threads', 4),
                    config.get('monitor_mode', 'local'),
                    config.get('remote_ip', None),
                    config.get('pcap_file', None)
                )
        return [], 4, 'local', None, None
    except Exception as e:
        logger.error(f"無法載入配置：{str(e)}")
        return [], 4, 'local', None, None

def get_local_ip():
    """獲取本機 IP 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        logger.debug(f"通過 socket 檢測到本機 IP：{local_ip}")
        return local_ip
    except Exception as e:
        logger.warning(f"通過 socket 無法獲取本機 IP：{str(e)}，嘗試使用 psutil")
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        logger.debug(f"通過 psutil 檢測到本機 IP：{addr.address}")
                        return addr.address
            logger.error("通過 psutil 未找到有效本機 IP")
            return None
        except Exception as e:
            logger.error(f"通過 psutil 無法獲取本機 IP：{str(e)}")
            return None

def validate_ip(ip):
    """驗證 IP 地址格式"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_multicast_or_broadcast(ip):
    """檢查 IP 是否為多播或廣播地址"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_multicast or ip == '255.255.255.255'
    except ValueError:
        return False

def get_training_features():
    """返回模型預期的特徵列表（79 個特徵，與訓練資料一致）"""
    features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
        'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
        'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
        'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
        'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
        'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
        'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
        'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
        'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'SimillarHTTP', 'Inbound'
    ]
    logger.debug(f"已定義訓練特徵：{features}，數量：{len(features)}")
    return features

def predict_flow(model, le, flow_df, training_features):
    """預測流量的標籤，確保特徵順序與訓練時一致"""
    try:
        scaler = joblib.load('C:\\IDS_defense\\models\\scaler.pkl')
        model_feature_names = model.get_booster().feature_names or training_features
        
        # 定義 CSV 欄位到訓練特徵的映射
        feature_mapping = {
            'Flow ID': 'Flow ID',  # CSV 和訓練資料一致，無需映射
            'Src IP': 'Source IP',
            'Src Port': 'Source Port',
            'Dst IP': 'Destination IP',
            'Dst Port': 'Destination Port',
            'Protocol': 'Protocol',
            'Timestamp': 'Timestamp',
            'Flow Duration': 'Flow Duration',
            'Tot Fwd Pkts': 'Total Fwd Packets',
            'Tot Bwd Pkts': 'Total Backward Packets',
            'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
            'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
            'Fwd Pkt Len Max': 'Fwd Packet Length Max',
            'Fwd Pkt Len Min': 'Fwd Packet Length Min',
            'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
            'Fwd Pkt Len Std': 'Fwd Packet Length Std',
            'Bwd Pkt Len Max': 'Bwd Packet Length Max',
            'Bwd Pkt Len Min': 'Bwd Packet Length Min',
            'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
            'Bwd Pkt Len Std': 'Bwd Packet Length Std',
            'Flow Byts/s': 'Flow Bytes/s',
            'Flow Pkts/s': 'Flow Packets/s',
            'Flow IAT Mean': 'Flow IAT Mean',
            'Flow IAT Std': 'Flow IAT Std',
            'Flow IAT Max': 'Flow IAT Max',
            'Flow IAT Min': 'Flow IAT Min',
            'Fwd IAT Tot': 'Fwd IAT Total',
            'Fwd IAT Mean': 'Fwd IAT Mean',
            'Fwd IAT Std': 'Fwd IAT Std',
            'Fwd IAT Max': 'Fwd IAT Max',
            'Fwd IAT Min': 'Fwd IAT Min',
            'Bwd IAT Tot': 'Bwd IAT Total',
            'Bwd IAT Mean': 'Bwd IAT Mean',
            'Bwd IAT Std': 'Bwd IAT Std',
            'Bwd IAT Max': 'Bwd IAT Max',
            'Bwd IAT Min': 'Bwd IAT Min',
            'Fwd PSH Flags': 'Fwd PSH Flags',
            'Bwd PSH Flags': 'Bwd PSH Flags',
            'Fwd URG Flags': 'Fwd URG Flags',
            'Bwd URG Flags': 'Bwd URG Flags',
            'Fwd Header Len': 'Fwd Header Length',
            'Bwd Header Len': 'Bwd Header Length',
            'Fwd Pkts/s': 'Fwd Packets/s',
            'Bwd Pkts/s': 'Bwd Packets/s',
            'Pkt Len Min': 'Min Packet Length',
            'Pkt Len Max': 'Max Packet Length',
            'Pkt Len Mean': 'Packet Length Mean',
            'Pkt Len Std': 'Packet Length Std',
            'Pkt Len Var': 'Packet Length Variance',
            'FIN Flag Cnt': 'FIN Flag Count',
            'SYN Flag Cnt': 'SYN Flag Count',
            'RST Flag Cnt': 'RST Flag Count',
            'PSH Flag Cnt': 'PSH Flag Count',
            'ACK Flag Cnt': 'ACK Flag Count',
            'URG Flag Cnt': 'URG Flag Count',
            'CWE Flag Count': 'CWE Flag Count',
            'ECE Flag Cnt': 'ECE Flag Count',
            'Down/Up Ratio': 'Down/Up Ratio',
            'Pkt Size Avg': 'Average Packet Size',
            'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
            'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
            'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
            'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
            'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
            'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
            'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
            'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
            'Subflow Fwd Pkts': 'Subflow Fwd Packets',
            'Subflow Fwd Byts': 'Subflow Fwd Bytes',
            'Subflow Bwd Pkts': 'Subflow Bwd Packets',
            'Subflow Bwd Byts': 'Subflow Bwd Bytes',
            'Init Fwd Win Byts': 'Init_Win_bytes_forward',
            'Init Bwd Win Byts': 'Init_Win_bytes_backward',
            'Fwd Act Data Pkts': 'act_data_pkt_fwd',
            'Fwd Seg Size Min': 'min_seg_size_forward',
            'Active Mean': 'Active Mean',
            'Active Std': 'Active Std',
            'Active Max': 'Active Max',
            'Active Min': 'Active Min',
            'Idle Mean': 'Idle Mean',
            'Idle Std': 'Idle Std',
            'Idle Max': 'Idle Max',
            'Idle Min': 'Idle Min',
            'SimillarHTTP': 'SimillarHTTP',
            'Inbound': 'Inbound'
        }
        
        # 將 CSV 欄位名稱映射到訓練特徵名稱
        flow_df = flow_df.rename(columns=feature_mapping)
        
        # 移除多餘特徵（例如 Flow ID, Src IP 等）
        extra_features = set(flow_df.columns) - set(model_feature_names)
        if extra_features:
            flow_df = flow_df.drop(columns=extra_features, errors='ignore')
            logger.debug(f"移除多餘特徵：{extra_features}")
        
        # 補充缺少特徵
        missing_features = set(model_feature_names) - set(flow_df.columns)
        for feat in missing_features:
            flow_df[feat] = 0.0
            logger.debug(f"補充缺少特徵：{feat}")
        
        # 確保特徵順序與訓練時一致
        flow_df = flow_df[model_feature_names]
        flow_df.fillna(0, inplace=True)
        
        # 標準化數據
        flow_scaled = scaler.transform(flow_df)
        preds = model.predict(flow_scaled)
        preds_labels = le.inverse_transform(preds)
        normalized_label = preds_labels[0].lower()
        logger.debug(f"預測結果（原始）：{preds_labels[0]}，標準化：{normalized_label}")
        return normalized_label
    except Exception as e:
        logger.error(f"預測失敗：{str(e)}")
        return None
def clean_flow_state(flow_state, timeout=120000000):
    """清理超過超時時間的流量狀態"""
    current_time = time.time() * 1e6
    expired_keys = [key for key, state in flow_state.items() if current_time - state['start_time'] > timeout]
    for key in expired_keys:
        del flow_state[key]
    logger.debug(f"已清理流量狀態，剩餘流量數：{len(flow_state)}")

def block_ip_local(ip_to_block, whitelist_ips):
    """在本機使用 netsh 封鎖 IP"""
    if ip_to_block in whitelist_ips:
        logger.info(f"IP {ip_to_block} 在白名單中，跳過封鎖")
        block_logger.info(f"IP {ip_to_block} 在白名單中，跳過封鎖")
        return False
    with lock:
        try:
            rule_name = f"IDS_Block_{ip_to_block.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_to_block}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"無法封鎖 IP {ip_to_block}：{result.stderr}")
                block_logger.error(f"無法封鎖 IP {ip_to_block}：{result.stderr}")
                return False
            logger.info(f"在本機成功封鎖 IP {ip_to_block}")
            block_logger.info(f"於 {datetime.now()} 在本機成功封鎖 IP {ip_to_block}")
            return True
        except Exception as e:
            logger.error(f"封鎖 IP {ip_to_block} 時發生錯誤：{str(e)}")
            block_logger.error(f"封鎖 IP {ip_to_block} 時發生錯誤：{str(e)}")
            return False

def unblock_ip_local(ip_to_unblock):
    """在本機使用 netsh 解除封鎖 IP"""
    with lock:
        try:
            rule_name = f"IDS_Block_{ip_to_unblock.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"無法解除封鎖 IP {ip_to_unblock}：{result.stderr}")
                block_logger.error(f"無法解除封鎖 IP {ip_to_unblock}：{result.stderr}")
                return False
            logger.info(f"在本機成功解除封鎖 IP {ip_to_unblock}")
            block_logger.info(f"於 {datetime.now()} 在本機成功解除封鎖 IP {ip_to_unblock}")
            return True
        except Exception as e:
            logger.error(f"解除封鎖 IP {ip_to_unblock} 時發生錯誤：{str(e)}")
            block_logger.error(f"解除封鎖 IP {ip_to_unblock} 時發生錯誤：{str(e)}")
            return False

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("本機與遠端入侵檢測系統")
        self.root.geometry("1200x800")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", padding=6, font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("TEntry", font=("Segoe UI", 10))
        self.style.configure("Treeview", font=("Segoe UI", 10))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        
        self.packet_table_tags = {
            'Benign': ('benign',),
            'Malicious': ('malicious',)
        }
        self.style.configure('benign.Treeview', background='#d4edda', foreground='#155724')
        self.style.configure('malicious.Treeview', background='#f8d7da', foreground='#721c24')
        
        self.model = joblib.load('C:\\IDS_defense\\models\\xgboost_model.pkl')
        self.le = joblib.load('C:\\IDS_defense\\models\\label_encoder.pkl')
        self.training_features = get_training_features()
        self.flow_state = {}
        self.sniffing = False
        self.sniff_thread = None
        self.auto_block = tk.BooleanVar(value=False)
        self.last_detected_ip = None
        self.interface_map = {}
        self.whitelist_ips = []
        self.packet_count = 0
        self.packet_rate = tk.StringVar(value="封包速率：0 packets/s")
        self.start_time = time.time()
        self.blocked_ips = set()
        self.local_ip = get_local_ip()
        self.packet_details = {}
        self.monitor_mode = tk.StringVar(value="local")
        self.remote_ip = tk.StringVar(value="")
        self.pcap_file = tk.StringVar(value="")
        self.pcap_dir = 'C:/IDS_defense/pcaps'
        self.csv_dir = 'C:/IDS_defense/csvs'
        self.current_pcap_packets = []
        self.processing_pcap = False
        self.pcap_interval_ms = tk.StringVar(value="1000")  # 預設 1000 毫秒
        self.last_pcap_time = time.time() * 1000  # 記錄上次生成 pcap 的時間（毫秒）
        self.whitelist_ips, max_threads, monitor_mode, remote_ip, pcap_file = load_config()
        self.max_threads_var = tk.StringVar(value=str(max_threads))
        self.monitor_mode.set(monitor_mode)
        self.remote_ip.set(remote_ip if remote_ip else "")
        self.pcap_file.set(pcap_file if pcap_file else "")
        self.executor = ThreadPoolExecutor(max_workers=max_threads)
        
        self.benign_count = 0
        self.malicious_count = 0
        self.packet_rates = []
        self.timestamps = []
        self.src_ips = Counter()
        
        self.monitor_window = None
        self.setup_gui()
    def apply_pcap_interval(self):
        """驗證並應用 PCAP 生成時間間隔"""
        try:
            interval = int(self.pcap_interval_ms.get())
            if interval <= 0:
                raise ValueError("間隔必須大於 0")
            logger.info(f"已設置 PCAP 生成間隔為 {interval} 毫秒")
            self.log_message(f"已設置 PCAP 生成間隔為 {interval} 毫秒")
        except ValueError as e:
            logger.error(f"無效的時間間隔：{str(e)}")
            self.log_message(f"無效的時間間隔：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"請輸入有效的正整數間隔（毫秒）"))
    def setup_gui(self):
        # 配置 root 的 grid
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # 新增時間間隔設置
        interval_frame = ttk.Frame(self.root)
        interval_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Label(interval_frame, text="生成 PCAP 間隔（毫秒）：").grid(row=0, column=0, sticky='w')
        interval_entry = ttk.Entry(interval_frame, textvariable=self.pcap_interval_ms, width=10)
        interval_entry.grid(row=0, column=1, sticky='w', padx=5)
        ttk.Button(interval_frame, text="應用間隔", command=self.apply_pcap_interval).grid(row=0, column=2, sticky='w')
        
        main_frame = ttk.Frame(self.root, padding=10, style="Main.TFrame")
        main_frame.grid(row=1, column=0, sticky="nsew")
        
        main_frame.grid_rowconfigure(2, weight=3)
        main_frame.grid_rowconfigure(4, weight=2)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 控制面板
        control_frame = ttk.LabelFrame(main_frame, text="控制面板", padding=10)
        control_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=5)
        control_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Button(control_frame, text="開啟圖形監控", command=self.toggle_monitor_window).grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        ttk.Label(control_frame, text=f"本機 IP：{self.local_ip if self.local_ip else '無法獲取'}").grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        monitor_frame = ttk.LabelFrame(control_frame, text="監控模式", padding=5)
        monitor_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=5)
        ttk.Radiobutton(monitor_frame, text="本機監控", value="local", variable=self.monitor_mode, command=self.toggle_monitor_mode).grid(row=0, column=0, padx=5, pady=5)
        ttk.Radiobutton(monitor_frame, text="遠端 IP 監控", value="remote", variable=self.monitor_mode, command=self.toggle_monitor_mode).grid(row=0, column=1, padx=5, pady=5)
        ttk.Radiobutton(monitor_frame, text="離線模式 (.pcap)", value="offline", variable=self.monitor_mode, command=self.toggle_monitor_mode).grid(row=0, column=2, padx=5, pady=5)
        self.remote_ip_label = ttk.Label(monitor_frame, text="遠端 IP：")
        self.remote_ip_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.remote_ip_entry = ttk.Entry(monitor_frame, textvariable=self.remote_ip)
        self.remote_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(monitor_frame, text="保存遠端 IP", command=self.save_remote_ip).grid(row=1, column=2, padx=5, pady=5)
        self.remote_ip_entry.bind("<Enter>", lambda e: self.show_tooltip(self.remote_ip_entry, "輸入要監控的遠端 IP 地址"))
        self.remote_ip_entry.bind("<Leave>", self.hide_tooltip)
        
        self.pcap_label = ttk.Label(monitor_frame, text="pcap 檔案：")
        self.pcap_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.pcap_entry = ttk.Entry(monitor_frame, textvariable=self.pcap_file, state="readonly")
        self.pcap_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.pcap_button = ttk.Button(monitor_frame, text="選擇 .pcap 檔案", command=self.select_pcap_file)
        self.pcap_button.grid(row=2, column=2, padx=5, pady=5)
        
        self.interface_label = ttk.Label(control_frame, text="網絡介面：")
        self.interface_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_combo.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.interface_combo.bind("<Enter>", lambda e: self.show_tooltip(self.interface_combo, "選擇要監控的網絡介面"))
        self.interface_combo.bind("<Leave>", self.hide_tooltip)
        
        ttk.Label(control_frame, text="白名單 IP（逗號分隔）：").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.whitelist_var = tk.StringVar(value=",".join(self.whitelist_ips))
        ttk.Entry(control_frame, textvariable=self.whitelist_var).grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(control_frame, text="保存白名單", command=self.save_whitelist).grid(row=4, column=2, padx=5, pady=5)
        control_frame.children['!entry'].bind("<Enter>", lambda e: self.show_tooltip(control_frame.children['!entry'], "輸入以逗號分隔的 IP 地址"))
        control_frame.children['!entry'].bind("<Leave>", self.hide_tooltip)
        
        ttk.Label(control_frame, text="要封鎖的 IP：").grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.block_ip_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.block_ip_var).grid(row=5, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(control_frame, text="封鎖 IP", command=self.manual_block_ip).grid(row=5, column=2, padx=5, pady=5)
        control_frame.children['!entry2'].bind("<Enter>", lambda e: self.show_tooltip(control_frame.children['!entry2'], "輸入要封鎖的 IP 地址"))
        control_frame.children['!entry2'].bind("<Leave>", self.hide_tooltip)
        
        ttk.Label(control_frame, text="要解除封鎖的 IP：").grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.unblock_ip_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.unblock_ip_var).grid(row=6, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(control_frame, text="解除封鎖 IP", command=self.unblock_ip).grid(row=6, column=2, padx=5, pady=5)
        control_frame.children['!entry3'].bind("<Enter>", lambda e: self.show_tooltip(control_frame.children['!entry3'], "輸入要解除封鎖的 IP 地址"))
        control_frame.children['!entry3'].bind("<Leave>", self.hide_tooltip)
        
        ttk.Label(control_frame, text="最大執行緒數：").grid(row=7, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(control_frame, textvariable=self.max_threads_var).grid(row=7, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(control_frame, text="應用執行緒數", command=self.apply_max_threads).grid(row=7, column=2, padx=5, pady=5)
        control_frame.children['!entry4'].bind("<Enter>", lambda e: self.show_tooltip(control_frame.children['!entry4'], "輸入執行緒數（1-16）"))
        control_frame.children['!entry4'].bind("<Leave>", self.hide_tooltip)
        
        ttk.Checkbutton(control_frame, text="自動封鎖惡意 IP", variable=self.auto_block).grid(row=8, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.block_button = ttk.Button(control_frame, text="封鎖最後檢測到的 IP", command=self.manual_block, state="disabled")
        self.block_button.grid(row=8, column=2, padx=5, pady=5)
        
        ttk.Button(control_frame, text="查看歷史異常報告", command=self.view_hazard_logs).grid(row=9, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        # 封包表格區域
        table_container = ttk.Frame(main_frame)
        table_container.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=5)
        table_container.grid_columnconfigure(0, weight=1)
        table_container.grid_columnconfigure(1, weight=1)
        table_container.grid_rowconfigure(0, weight=1)
        
        benign_table_frame = ttk.LabelFrame(table_container, text="正常封包", padding=10)
        benign_table_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        benign_table_frame.grid_columnconfigure(0, weight=1)
        benign_table_frame.grid_rowconfigure(0, weight=1)
        
        self.benign_table = ttk.Treeview(
            benign_table_frame,
            columns=("Time", "Source IP", "Destination IP", "Protocol", "Label"),
            show="headings",
            style="benign.Treeview"
        )
        self.benign_table.heading("Time", text="時間")
        self.benign_table.heading("Source IP", text="來源 IP")
        self.benign_table.heading("Destination IP", text="目的 IP")
        self.benign_table.heading("Protocol", text="協議")
        self.benign_table.heading("Label", text="標籤")
        self.benign_table.column("Time", width=150)
        self.benign_table.column("Source IP", width=100)
        self.benign_table.column("Destination IP", width=100)
        self.benign_table.column("Protocol", width=80)
        self.benign_table.column("Label", width=100)
        self.benign_table.grid(row=0, column=0, sticky="nsew")
        self.benign_table.bind("<Double-1>", self.show_packet_details)
        
        benign_scroll_y = ttk.Scrollbar(benign_table_frame, orient="vertical", command=self.benign_table.yview)
        benign_scroll_y.grid(row=0, column=1, sticky="ns")
        benign_scroll_x = ttk.Scrollbar(benign_table_frame, orient="horizontal", command=self.benign_table.xview)
        benign_scroll_x.grid(row=1, column=0, sticky="ew")
        self.benign_table.configure(yscrollcommand=benign_scroll_y.set, xscrollcommand=benign_scroll_x.set)
        
        malicious_table_frame = ttk.LabelFrame(table_container, text="異常封包", padding=10)
        malicious_table_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        malicious_table_frame.grid_columnconfigure(0, weight=1)
        malicious_table_frame.grid_rowconfigure(0, weight=1)
        
        self.malicious_table = ttk.Treeview(
            malicious_table_frame,
            columns=("Time", "Source IP", "Destination IP", "Protocol", "Label"),
            show="headings",
            style="malicious.Treeview"
        )
        self.malicious_table.heading("Time", text="時間")
        self.malicious_table.heading("Source IP", text="來源 IP")
        self.malicious_table.heading("Destination IP", text="目的 IP")
        self.malicious_table.heading("Protocol", text="協議")
        self.malicious_table.heading("Label", text="標籤")
        self.malicious_table.column("Time", width=150)
        self.malicious_table.column("Source IP", width=100)
        self.malicious_table.column("Destination IP", width=100)
        self.malicious_table.column("Protocol", width=80)
        self.malicious_table.column("Label", width=100)
        self.malicious_table.grid(row=0, column=0, sticky="nsew")
        self.malicious_table.bind("<Double-1>", self.show_packet_details)
        
        malicious_scroll_y = ttk.Scrollbar(malicious_table_frame, orient="vertical", command=self.malicious_table.yview)
        malicious_scroll_y.grid(row=0, column=1, sticky="ns")
        malicious_scroll_x = ttk.Scrollbar(malicious_table_frame, orient="horizontal", command=self.malicious_table.xview)
        malicious_scroll_x.grid(row=1, column=0, sticky="ew")
        self.malicious_table.configure(yscrollcommand=malicious_scroll_y.set, xscrollcommand=malicious_scroll_x.set)
        
        ttk.Label(main_frame, textvariable=self.packet_rate).grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        
        self.start_button = ttk.Button(main_frame, text="開始檢測", command=self.toggle_sniffing)
        self.start_button.grid(row=3, column=2, padx=5, pady=5, sticky="e")
        
        log_frame = ttk.LabelFrame(main_frame, text="檢測日誌", padding=10)
        log_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=5)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_frame, height=10, font=("Segoe UI", 10), bg="#f8f9fa", fg="#212529")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.gui_handler = TextHandler(self.log_text)
        self.gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(self.gui_handler)
        hazard_logger.addHandler(self.gui_handler)
        block_logger.addHandler(self.gui_handler)
        
        self.update_interfaces()
        self.update_packet_rate()
        self.tooltip_window = None
        self.toggle_monitor_mode()

    def toggle_monitor_window(self):
        """開啟或關閉圖形監控視窗"""
        if self.monitor_window is None or not self.monitor_window.winfo_exists():
            self.monitor_window = tk.Toplevel(self.root)
            self.monitor_window.title("圖形監控面板")
            self.monitor_window.geometry("1200x400")
            self.setup_graphical_monitor(self.monitor_window)
            self.monitor_window.protocol("WM_DELETE_WINDOW", self.close_monitor_window)
            self.log_message("已開啟圖形監控視窗")
        else:
            self.close_monitor_window()

    def close_monitor_window(self):
        """關閉圖形監控視窗"""
        if self.monitor_window:
            self.monitor_window.destroy()
            self.monitor_window = None
            self.rate_ani = None
            self.pie_ani = None
            self.bar_ani = None
            self.log_message("已關閉圖形監控視窗")

    def setup_graphical_monitor(self, parent):
        """設置圖形監控面板"""
        monitor_frame = ttk.LabelFrame(parent, text="圖形監控面板", padding=10)
        monitor_frame.grid(row=0, column=0, sticky="nsew", pady=5)
        monitor_frame.grid_columnconfigure(0, weight=1)
        monitor_frame.grid_columnconfigure(1, weight=1)
        monitor_frame.grid_columnconfigure(2, weight=1)
        monitor_frame.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        
        self.rate_fig, self.rate_ax = plt.subplots(figsize=(4, 3))
        self.rate_line, = self.rate_ax.plot([], [], 'b-')
        self.rate_ax.set_title("即時封包速率")
        self.rate_ax.set_xlabel("時間 (秒)")
        self.rate_ax.set_ylabel("速率 (packets/s)")
        self.rate_canvas = FigureCanvasTkAgg(self.rate_fig, master=monitor_frame)
        self.rate_canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew", padx=5)
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(4, 3))
        self.pie_ax.set_title("正常 vs 惡意封包")
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=monitor_frame)
        self.pie_canvas.get_tk_widget().grid(row=0, column=1, sticky="nsew", padx=5)
        
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(4, 3))
        self.bar_ax.set_title("頂部來源 IP")
        self.bar_ax.set_xlabel("IP 地址")
        self.bar_ax.set_ylabel("計數")
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=monitor_frame)
        self.bar_canvas.get_tk_widget().grid(row=0, column=2, sticky="nsew", padx=5)
        
        self.rate_ani = FuncAnimation(self.rate_fig, self.update_rate_chart, interval=1000)
        self.pie_ani = FuncAnimation(self.pie_fig, self.update_pie_chart, interval=1000)
        self.bar_ani = FuncAnimation(self.bar_fig, self.update_bar_chart, interval=1000)

    def update_rate_chart(self, frame):
        """更新即時封包速率線圖"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        current_time = len(self.timestamps)
        self.timestamps.append(current_time)
        elapsed = time.time() - self.start_time
        rate = self.packet_count / elapsed if elapsed > 0 else 0
        self.packet_rates.append(rate)
        if len(self.packet_rates) > 60:
            self.packet_rates.pop(0)
            self.timestamps.pop(0)
        self.rate_line.set_data(self.timestamps, self.packet_rates)
        self.rate_ax.relim()
        self.rate_ax.autoscale_view()
        self.rate_canvas.draw()

    def update_pie_chart(self, frame):
        """更新正常 vs 惡意封包餅圖"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        total = self.benign_count + self.malicious_count
        if total > 0:
            labels = ['正常', '惡意']
            sizes = [self.benign_count, self.malicious_count]
            self.pie_ax.clear()
            self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['#d4edda', '#f8d7da'])
            self.pie_ax.set_title("正常 vs 惡意封包")
        self.pie_canvas.draw()

    def update_bar_chart(self, frame):
        """更新頂部來源 IP 條形圖，排除本機 IP"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        filtered_ips = Counter({ip: count for ip, count in self.src_ips.items() if ip != self.local_ip})
        top_ips = filtered_ips.most_common(5)
        if top_ips:
            ips, counts = zip(*top_ips)
            self.bar_ax.clear()
            self.bar_ax.bar(ips, counts, color='skyblue')
            self.bar_ax.set_title("頂部來源 IP")
            self.bar_ax.set_xlabel("IP 地址")
            self.bar_ax.set_ylabel("計數")
            plt.setp(self.bar_ax.get_xticklabels(), rotation=45, ha="right")
        self.bar_canvas.draw()

    def toggle_monitor_mode(self):
        """根據監控模式顯示或隱藏相關元素"""
        mode = self.monitor_mode.get()
        if mode == "local":
            self.remote_ip_label.grid_remove()
            self.remote_ip_entry.grid_remove()
            self.remote_ip_entry.master.children['!button'].grid_remove()
            self.pcap_label.grid_remove()
            self.pcap_entry.grid_remove()
            self.pcap_button.grid_remove()
            self.interface_label.grid()
            self.interface_combo.grid()
            self.log_message("切換到本機監控模式")
        elif mode == "remote":
            self.remote_ip_label.grid()
            self.remote_ip_entry.grid()
            self.remote_ip_entry.master.children['!button'].grid()
            self.pcap_label.grid_remove()
            self.pcap_entry.grid_remove()
            self.pcap_button.grid_remove()
            self.interface_label.grid()
            self.interface_combo.grid()
            self.log_message("切換到遠端 IP 監控模式")
        elif mode == "offline":
            self.remote_ip_label.grid_remove()
            self.remote_ip_entry.grid_remove()
            self.remote_ip_entry.master.children['!button'].grid_remove()
            self.pcap_label.grid()
            self.pcap_entry.grid()
            self.pcap_button.grid()
            self.interface_label.grid_remove()
            self.interface_combo.grid_remove()
            self.log_message("切換到離線模式 (.pcap 分析)")
        save_config(self.whitelist_ips, int(self.max_threads_var.get()), mode, self.remote_ip.get(), self.pcap_file.get())

    def select_pcap_file(self):
        """瀏覽並選擇 .pcap 檔案"""
        file_path = filedialog.askopenfilename(title="選擇 .pcap 檔案", filetypes=[("PCAP files", "*.pcap *.pcapng")])
        if file_path:
            self.pcap_file.set(file_path)
            save_config(self.whitelist_ips, int(self.max_threads_var.get()), self.monitor_mode.get(), self.remote_ip.get(), file_path)
            self.log_message(f"已選擇 pcap 檔案：{file_path}")
            messagebox.showinfo("成功", f"已選擇 pcap 檔案：{file_path}")
        else:
            self.log_message("未選擇 pcap 檔案")

    def save_remote_ip(self):
        """保存遠端 IP 並驗證格式"""
        ip = self.remote_ip.get().strip()
        if not ip:
            self.log_message("未輸入遠端 IP")
            messagebox.showerror("錯誤", "請輸入遠端 IP")
            return
        if not validate_ip(ip):
            self.log_message(f"無效的 IP 地址：{ip}")
            messagebox.showerror("錯誤", f"無效的 IP 地址：{ip}")
            return
        save_config(self.whitelist_ips, int(self.max_threads_var.get()), self.monitor_mode.get(), ip, self.pcap_file.get())
        self.log_message(f"遠端 IP 已保存：{ip}")
        messagebox.showinfo("成功", f"遠端 IP 已保存：{ip}")

    def show_tooltip(self, widget, text):
        """顯示工具提示"""
        x, y, _, _ = widget.bbox("insert")
        x += widget.winfo_rootx() + 25
        y += widget.winfo_rooty() + 25
        self.tooltip_window = tk.Toplevel(widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip_window, text=text, background="#ffffe0", relief="solid", borderwidth=1, font=("Segoe UI", 9))
        label.pack()

    def hide_tooltip(self, event=None):
        """隱藏工具提示"""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    def view_hazard_logs(self):
        """顯示歷史異常報告視窗"""
        hazard_window = tk.Toplevel(self.root)
        hazard_window.title("歷史異常報告")
        hazard_window.geometry("800x600")
        
        hazard_frame = ttk.Frame(hazard_window, padding=10)
        hazard_frame.grid(row=0, column=0, sticky="nsew")
        hazard_window.grid_rowconfigure(0, weight=1)
        hazard_window.grid_columnconfigure(0, weight=1)
        hazard_frame.grid_rowconfigure(2, weight=1)
        hazard_frame.grid_columnconfigure(0, weight=1)
        
        log_select_frame = ttk.LabelFrame(hazard_frame, text="選擇日誌檔案", padding=5)
        log_select_frame.grid(row=0, column=0, sticky="ew", pady=5)
        log_select_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(log_select_frame, text="日誌檔案：").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.log_file_var = tk.StringVar()
        self.log_file_combo = ttk.Combobox(log_select_frame, textvariable=self.log_file_var, state="readonly")
        self.log_file_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(log_select_frame, text="刷新日誌列表", command=self.update_log_files).grid(row=0, column=2, padx=5, pady=5)
        self.log_file_combo.bind("<<ComboboxSelected>>", self.display_log_content)
        
        log_content_frame = ttk.LabelFrame(hazard_frame, text="日誌內容", padding=5)
        log_content_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        log_content_frame.grid_columnconfigure(0, weight=1)
        log_content_frame.grid_rowconfigure(0, weight=1)
        
        self.hazard_log_text = tk.Text(log_content_frame, height=20, font=("Segoe UI", 10), wrap="none")
        self.hazard_log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll_y = ttk.Scrollbar(log_content_frame, orient="vertical", command=self.hazard_log_text.yview)
        log_scroll_y.grid(row=0, column=1, sticky="ns")
        log_scroll_x = ttk.Scrollbar(log_content_frame, orient="horizontal", command=self.hazard_log_text.xview)
        log_scroll_x.grid(row=1, column=0, sticky="ew")
        self.hazard_log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)
        
        self.update_log_files()

    def update_log_files(self):
        """更新日誌檔案下拉選單"""
        try:
            log_files = [f for f in os.listdir(LOG_DIR) if f.startswith('hazard_') and f.endswith('.log')]
            log_files.sort(reverse=True)
            self.log_file_combo['values'] = log_files
            if log_files:
                self.log_file_var.set(log_files[0])
                self.display_log_content()
            else:
                self.log_file_var.set("")
                self.hazard_log_text.config(state='normal')
                self.hazard_log_text.delete(1.0, tk.END)
                self.hazard_log_text.insert(tk.END, "未找到歷史異常日誌檔案")
                self.hazard_log_text.config(state='disabled')
            self.log_message("已刷新歷史異常日誌列表")
        except Exception as e:
            self.log_message(f"無法刷新日誌檔案列表：{str(e)}")
            messagebox.showerror("錯誤", f"無法刷新日誌檔案列表：{str(e)}")

    def display_log_content(self, event=None):
        """顯示選定日誌檔案的內容"""
        selected_log = self.log_file_var.get()
        if not selected_log:
            return
        try:
            log_path = os.path.join(LOG_DIR, selected_log)
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.hazard_log_text.config(state='normal')
            self.hazard_log_text.delete(1.0, tk.END)
            self.hazard_log_text.insert(tk.END, content)
            self.hazard_log_text.config(state='disabled')
            self.log_message(f"顯示日誌檔案：{selected_log}")
        except Exception as e:
            self.log_message(f"無法讀取日誌檔案 {selected_log}：{str(e)}")
            messagebox.showerror("錯誤", f"無法讀取日誌檔案 {selected_log}：{str(e)}")

    def show_packet_details(self, event):
        """顯示選中封包的詳細資訊"""
        widget = event.widget
        selected_item = widget.selection()
        if not selected_item:
            return
        item = selected_item[0]
        values = widget.item(item, "values")
        packet_id = values[0]
        if packet_id in self.packet_details:
            details = self.packet_details[packet_id]
            detail_window = tk.Toplevel(self.root)
            detail_window.title("封包詳細資訊")
            detail_window.geometry("600x400")
            
            detail_frame = ttk.Frame(detail_window, padding=10)
            detail_frame.grid(row=0, column=0, sticky="nsew")
            detail_window.grid_rowconfigure(0, weight=1)
            detail_window.grid_columnconfigure(0, weight=1)
            detail_frame.grid_rowconfigure(1, weight=1)
            detail_frame.grid_columnconfigure(0, weight=1)
            
            basic_info = ttk.LabelFrame(detail_frame, text="基本資訊", padding=5)
            basic_info.grid(row=0, column=0, sticky="ew", pady=5)
            ttk.Label(basic_info, text=f"時間：{values[0]}").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"來源 IP：{values[1]}").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"目的 IP：{values[2]}").grid(row=2, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"協議：{values[3]}").grid(row=3, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"標籤：{values[4]}").grid(row=4, column=0, sticky="w", padx=5, pady=2)
            
            feature_frame = ttk.LabelFrame(detail_frame, text="特徵資訊", padding=5)
            feature_frame.grid(row=1, column=0, sticky="nsew", pady=5)
            feature_text = tk.Text(feature_frame, height=10, font=("Segoe UI", 10), wrap="none")
            feature_text.grid(row=0, column=0, sticky="nsew")
            feature_scroll_y = ttk.Scrollbar(feature_frame, orient="vertical", command=feature_text.yview)
            feature_scroll_y.grid(row=0, column=1, sticky="ns")
            feature_scroll_x = ttk.Scrollbar(feature_frame, orient="horizontal", command=feature_text.xview)
            feature_scroll_x.grid(row=1, column=0, sticky="ew")
            feature_text.configure(yscrollcommand=feature_scroll_y.set, xscrollcommand=feature_scroll_x.set)
            feature_frame.grid_columnconfigure(0, weight=1)
            feature_frame.grid_rowconfigure(0, weight=1)
            
            for feature, value in details['features'].items():
                feature_text.insert(tk.END, f"{feature}: {value}\n")
            feature_text.config(state='disabled')
            
            raw_frame = ttk.LabelFrame(detail_frame, text="原始數據", padding=5)
            raw_frame.grid(row=2, column=0, sticky="nsew", pady=5)
            raw_text = tk.Text(raw_frame, height=5, font=("Courier New", 10), wrap="none")
            raw_text.grid(row=0, column=0, sticky="nsew")
            raw_scroll_y = ttk.Scrollbar(raw_frame, orient="vertical", command=raw_text.yview)
            raw_scroll_y.grid(row=0, column=1, sticky="ns")
            raw_scroll_x = ttk.Scrollbar(raw_frame, orient="horizontal", command=raw_text.xview)
            raw_scroll_x.grid(row=1, column=0, sticky="ew")
            raw_text.configure(yscrollcommand=raw_scroll_y.set, xscrollcommand=raw_scroll_x.set)
            raw_frame.grid_columnconfigure(0, weight=1)
            raw_frame.grid_rowconfigure(0, weight=1)
            
            hex_data = details['raw_data']
            ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in details['packet'].build())
            for i in range(0, len(hex_data), 32):
                hex_line = hex_data[i:i+32]
                ascii_line = ascii_data[i//2:i//2+16]
                raw_text.insert(tk.END, f"{hex_line:<48} {ascii_line}\n")
            raw_text.config(state='disabled')
            logger.debug(f"已顯示封包詳細資訊，時間戳：{packet_id}")

    def update_packet_rate(self):
        """更新 GUI 中的封包處理速率"""
        if self.sniffing:
            elapsed_time = time.time() - self.start_time
            rate = self.packet_count / elapsed_time if elapsed_time > 0 else 0
            self.packet_rate.set(f"封包速率：{rate:.2f} packets/s")
            self.packet_count = 0
            self.start_time = time.time()
        self.root.after(1000, self.update_packet_rate)

    def apply_max_threads(self):
        """應用新的最大執行緒數"""
        try:
            max_threads = int(self.max_threads_var.get())
            if max_threads < 1 or max_threads > 16:
                self.log_message("最大執行緒數必須在 1 到 16 之間")
                messagebox.showerror("錯誤", "最大執行緒數必須在 1 到 16 之間")
                return
            self.executor = ThreadPoolExecutor(max_workers=max_threads)
            save_config(self.whitelist_ips, max_threads, self.monitor_mode.get(), self.remote_ip.get(), self.pcap_file.get())
            self.log_message(f"最大執行緒數更新為：{max_threads}")
            messagebox.showinfo("成功", f"最大執行緒數更新為：{max_threads}")
        except ValueError:
            self.log_message("請輸入有效的最大執行緒數")
            messagebox.showerror("錯誤", "請輸入有效的最大執行緒數")

    def get_interfaces(self):
        """獲取可用網絡介面"""
        interfaces = []
        try:
            scapy_interfaces = {iface.name: iface for iface in conf.ifaces.data.values()}
            logger.debug(f"Scapy 檢測到的介面：{list(scapy_interfaces.keys())}")
            if not scapy_interfaces:
                logger.warning("Scapy 未檢測到任何介面")
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}")
            interface_map = {}
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, f"{subkey_name}\\Connection")
                    friendly_name = winreg.QueryValueEx(subkey, "Name")[0]
                    interface_map[subkey_name] = friendly_name
                    winreg.CloseKey(subkey)
                except:
                    continue
            winreg.CloseKey(key)
            winreg.CloseKey(reg)
            for guid, friendly_name in interface_map.items():
                scapy_iface_name = f"\\Device\\NPF_{guid}"
                if scapy_iface_name in scapy_interfaces:
                    interfaces.append((friendly_name, scapy_iface_name))
                else:
                    if guid in scapy_interfaces:
                        interfaces.append((friendly_name, guid))
            if not interfaces:
                logger.warning("Scapy/registry 未檢測到任何介面，嘗試使用 psutil")
                self.log_message("未檢測到任何介面，嘗試使用 psutil")
                for iface in psutil.net_if_addrs().keys():
                    interfaces.append((iface, iface))
            if interfaces:
                logger.debug(f"可用介面：{interfaces}")
                return interfaces
            else:
                logger.error("未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                self.log_message("未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                messagebox.showerror("錯誤", "未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                return []
        except Exception as e:
            logger.error(f"無法獲取介面：{str(e)}")
            self.log_message(f"無法獲取介面：{str(e)}")
            messagebox.showerror("錯誤", f"無法獲取介面：{str(e)}")
            return []

    def log_message(self, message):
        """在日誌視窗中顯示訊息"""
        try:
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state='disabled')
        except AttributeError:
            logger.warning(f"無法記錄到 GUI：{message}")

    def update_interfaces(self):
        """更新網絡介面選單"""
        for _ in range(3):
            interfaces = self.get_interfaces()
            if interfaces:
                self.interface_map = {friendly_name: scapy_iface for friendly_name, scapy_iface in interfaces}
                self.interface_combo['values'] = list(self.interface_map.keys())
                if interfaces:
                    self.interface_var.set(list(self.interface_map.keys())[0])
                    self.log_message(f"檢測到 {len(interfaces)} 個網絡介面")
                    return
                else:
                    self.interface_var.set("")
                    self.log_message("無可用網絡介面")
                time.sleep(2)
        self.log_message("多次嘗試後仍無法檢測到網絡介面，請檢查 Npcap 和管理員權限")
        messagebox.showerror("錯誤", "無法檢測到網絡介面，請檢查 Npcap 和管理員權限")

    def save_whitelist(self):
        """保存白名單 IP 到配置文件"""
        whitelist_input = self.whitelist_var.get()
        self.whitelist_ips = [ip.strip() for ip in whitelist_input.split(",") if ip.strip()]
        max_threads = int(self.max_threads_var.get()) if self.max_threads_var.get().isdigit() else 4
        save_config(self.whitelist_ips, max_threads, self.monitor_mode.get(), self.remote_ip.get(), self.pcap_file.get())
        self.log_message(f"白名單 IP 已更新：{self.whitelist_ips}")
        messagebox.showinfo("成功", "白名單 IP 已保存")

    def manual_block_ip(self):
        """手動封鎖指定的 IP"""
        ip_to_block = self.block_ip_var.get()
        if not ip_to_block:
            self.log_message("未輸入要封鎖的 IP")
            self.root.after(0, lambda: messagebox.showerror("錯誤", "請輸入要封鎖的 IP"))
            return
        threading.Thread(target=self._block_ip_thread, args=(ip_to_block,), daemon=True).start()

    def _block_ip_thread(self, ip_to_block):
        """在獨立執行緒中封鎖 IP"""
        try:
            with lock:
                if block_ip_local(ip_to_block, self.whitelist_ips):
                    self.blocked_ips.add(ip_to_block)
                    self.log_message(f"已手動封鎖 IP {ip_to_block}")
                    self.root.after(0, lambda: messagebox.showinfo("成功", f"已封鎖 IP {ip_to_block}"))
                else:
                    self.log_message(f"無法封鎖 IP {ip_to_block}（可能在白名單中或命令失敗）")
                    self.root.after(0, lambda: messagebox.showerror("錯誤", f"無法封鎖 IP {ip_to_block}（可能在白名單中或命令失敗）"))
        except Exception as e:
            error_msg = f"手動封鎖 IP {ip_to_block} 失敗：{str(e)}"
            logger.error(error_msg)
            block_logger.error(error_msg)
            self.log_message(error_msg)
            self.root.after(0, lambda: messagebox.showerror("錯誤", error_msg))

    def manual_block(self):
        """手動封鎖最後檢測到的惡意 IP"""
        if not self.last_detected_ip:
            self.log_message("無最後檢測到的 IP")
            self.root.after(0, lambda: messagebox.showerror("錯誤", "無最後檢測到的 IP"))
            return
        threading.Thread(target=self._block_ip_thread, args=(self.last_detected_ip,), daemon=True).start()

    def unblock_ip(self):
        """解除封鎖指定的 IP"""
        ip_to_unblock = self.unblock_ip_var.get()
        if not ip_to_unblock:
            self.log_message("未輸入要解除封鎖的 IP")
            self.root.after(0, lambda: messagebox.showerror("錯誤", "請輸入要解除封鎖的 IP"))
            return
        try:
            if unblock_ip_local(ip_to_unblock):
                self.blocked_ips.discard(ip_to_unblock)
                self.log_message(f"已解除封鎖 IP {ip_to_unblock}")
                self.root.after(0, lambda: messagebox.showinfo("成功", f"已解除封鎖 IP {ip_to_unblock}"))
            else:
                self.log_message(f"無找到要解除封鎖的 IP {ip_to_unblock} 的規則")
                self.root.after(0, lambda: messagebox.showerror("錯誤", f"無找到要解除封鎖的 IP {ip_to_unblock} 的規則"))
        except Exception as e:
            error_msg = f"解除封鎖 IP {ip_to_unblock} 失敗：{str(e)}"
            logger.error(error_msg)
            block_logger.error(error_msg)
            self.log_message(error_msg)
            self.root.after(0, lambda: messagebox.showerror("錯誤", error_msg))

    def clear_packet_tables(self):
        """清理封包表格和相關統計數據"""
        try:
            # 清理正常封包表格
            for item in self.benign_table.get_children():
                self.benign_table.delete(item)
            
            # 清理異常封包表格
            for item in self.malicious_table.get_children():
                self.malicious_table.delete(item)
            
            # 清理封包詳細資訊
            self.packet_details.clear()
            
            # 重置統計數據
            self.benign_count = 0
            self.malicious_count = 0
            self.src_ips.clear()
            self.packet_rates = []
            self.timestamps = []
            self.packet_count = 0
            self.start_time = time.time()  # 重置封包速率計算的開始時間
            
            self.log_message("已清理封包表格和相關統計資料")
            messagebox.showinfo("成功", "封包表格已清理")
        except Exception as e:
            error_msg = f"清理封包表格失敗：{str(e)}"
            logger.error(error_msg)
            self.log_message(error_msg)
            messagebox.showerror("錯誤", error_msg)

    def add_packet_to_table(self, src_ip, dst_ip, proto, label, features, packet):
        """將封包資訊添加到對應的表格（正常或異常）並儲存詳細資訊，並更新統計"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            is_benign = label.lower() == 'benign'
            tag = 'benign' if is_benign else 'malicious'
            table = self.benign_table if is_benign else self.malicious_table
            item_id = table.insert("", tk.END, values=(timestamp, src_ip, dst_ip, proto, label if label else "未知"), tags=(tag,))
            if packet:
                raw_data = hexlify(bytes(packet)).decode('ascii')
                self.packet_details[timestamp] = {
                    'features': features,
                    'raw_data': raw_data,
                    'packet': packet
                }
            else:
                self.packet_details[timestamp] = {
                    'features': features,
                    'raw_data': 'N/A',
                    'packet': None
                }
            if is_benign:
                self.benign_count += 1
            else:
                self.malicious_count += 1
            self.src_ips[src_ip] += 1
            for tbl in [self.benign_table, self.malicious_table]:
                if len(tbl.get_children()) > 100:
                    oldest_item = tbl.get_children()[0]
                    oldest_timestamp = tbl.item(oldest_item, "values")[0]
                    tbl.delete(oldest_item)
                    if oldest_timestamp in self.packet_details:
                        del self.packet_details[oldest_timestamp]
            logger.debug(f"已添加封包到 {tag} 表格：來源={src_ip}, 目的={dst_ip}, 標籤={label}")
        except Exception as e:
            logger.error(f"無法將封包添加到表格：{str(e)}")
            self.log_message(f"無法將封包添加到表格：{str(e)}")

    def toggle_sniffing(self):
        """開始或停止封包嗅探或 pcap 分析"""
        if not self.sniffing:
            mode = self.monitor_mode.get()
            if mode == "offline":
                if not self.pcap_file.get():
                    self.log_message("離線模式下未選擇 pcap 檔案")
                    messagebox.showerror("錯誤", "請選擇 .pcap 檔案")
                    return
                self.sniffing = True
                self.start_button.config(text="停止檢測")
                self.sniff_thread = threading.Thread(target=self.load_pcap, daemon=True)
                self.sniff_thread.start()
                self.log_message("開始離線 pcap 分析")
            else:
                if not self.local_ip:
                    self.log_message("無法獲取本機 IP")
                    self.root.after(0, lambda: messagebox.showerror("錯誤", "無法獲取本機 IP"))
                    return
                if not self.interface_var.get():
                    self.log_message("未選擇網絡介面")
                    self.root.after(0, lambda: messagebox.showerror("錯誤", "請選擇網絡介面"))
                    return
                if mode == "remote" and not validate_ip(self.remote_ip.get()):
                    self.log_message("遠端監控模式下必須提供有效的遠端 IP")
                    self.root.after(0, lambda: messagebox.showerror("錯誤", "請輸入有效的遠端 IP"))
                    return
                self.sniffing = True
                self.start_button.config(text="停止檢測")
                self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
                self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
                self.sniff_thread.start()
                self.process_thread.start()
                self.log_message(f"開始檢測（模式：{mode}）")
        else:
            self.sniffing = False
            self.start_button.config(text="開始檢測")
            self.block_button.config(state="disabled")
            packet_queue.put(None)
            self.blocked_ips.clear()
            self.packet_details.clear()
            self.current_pcap_packets = []
            self.benign_count = 0
            self.malicious_count = 0
            self.packet_rates = []
            self.timestamps = []
            self.src_ips.clear()
            self.log_message("停止檢測")

    def start_sniffing(self):
        """在獨立執行緒中開始封包嗅探"""
        try:
            interface = self.interface_map.get(self.interface_var.get())
            if not interface:
                raise ValueError("無效的網絡介面")
            sniff(iface=interface, prn=lambda pkt: packet_queue.put(pkt), store=0)
        except Exception as e:
            logger.error(f"嗅探失敗：{str(e)}")
            self.log_message(f"嗅探失敗：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"嗅探失敗：{str(e)}"))

    def load_pcap(self):
        """在獨立執行緒中讀取 pcap 檔案並處理"""
        try:
            pcap_path = self.pcap_file.get()
            if not os.path.exists(pcap_path):
                raise FileNotFoundError(f"pcap 檔案不存在：{pcap_path}")
            self.current_pcap_packets = rdpcap(pcap_path)
            logger.debug(f"已載入 pcap 檔案：{pcap_path}，總封包數：{len(self.current_pcap_packets)}")
            self.log_message(f"已載入 pcap 檔案：{pcap_path}，總封包數：{len(self.current_pcap_packets)}")
            self.executor.submit(self.process_pcap_to_csv)
        except Exception as e:
            logger.error(f"載入 pcap 失敗：{str(e)}")
            self.log_message(f"載入 pcap 失敗：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"載入 pcap 失敗：{str(e)}"))
            self.sniffing = False
            self.root.after(0, lambda: self.start_button.config(text="開始檢測"))
            self.sniffing = False
            self.root.after(0, lambda: self.start_button.config(text="開始檢測"))

    def process_packets(self):
        """從隊列中處理封包"""
        while self.sniffing:
            try:
                packet = packet_queue.get(timeout=1)
                if packet is None:
                    break
                self.executor.submit(self.packet_callback, packet)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"從隊列處理封包時發生錯誤：{str(e)}")
                self.log_message(f"從隊列處理封包時發生錯誤：{str(e)}")

    def packet_callback(self, packet):
        """處理每個捕獲的封包，累積到 current_pcap_packets 並根據時間間隔觸發 pcap 處理"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                
                # 過濾無效或多播/廣播封包
                if src_ip == '0.0.0.0' or is_multicast_or_broadcast(dst_ip):
                    logger.debug(f"跳過無效或多播/廣播封包：來源={src_ip}, 目的={dst_ip}, 協議={proto}")
                    return
                
                # 檢查白名單
                if src_ip in self.whitelist_ips or dst_ip in self.whitelist_ips:
                    logger.debug(f"跳過白名單封包：來源={src_ip}, 目的={dst_ip}")
                    return
                
                # 根據監控模式過濾封包
                mode = self.monitor_mode.get()
                if mode != "offline":
                    if mode == "local":
                        if src_ip != self.local_ip and dst_ip != self.local_ip:
                            logger.debug(f"跳過不涉及本機 IP {self.local_ip} 的封包：來源={src_ip}, 目的={dst_ip}")
                            return
                    elif mode == "remote":
                        if src_ip != self.remote_ip.get() and dst_ip != self.remote_ip.get():
                            logger.debug(f"跳過不涉及遠端 IP {self.remote_ip.get()} 的封包：來源={src_ip}, 目的={dst_ip}")
                            return
                
                proto_name = 'TCP' if TCP in packet else 'UDP' if UDP in packet else str(proto)
                
                # 累積封包
                self.current_pcap_packets.append(packet)
                self.packet_count += 1
                self.src_ips[src_ip] += 1
                
                # 檢查是否達到時間間隔
                current_time_ms = time.time() * 1000
                try:
                    interval_ms = int(self.pcap_interval_ms.get())
                except ValueError:
                    interval_ms = 1000  # 預設 1000 毫秒
                if current_time_ms - self.last_pcap_time >= interval_ms:
                    self.executor.submit(self.process_pcap_to_csv)
                    self.last_pcap_time = current_time_ms
                    
            clean_flow_state(self.flow_state)
        except Exception as e:
            logger.error(f"封包處理失敗：{str(e)}")
            self.log_message(f"封包處理失敗：{str(e)}")

    def process_pcap_to_csv(self):
        """將累積的封包儲存為 .pcap 並轉換為 .csv，然後觸發流量檢測"""
        if not self.current_pcap_packets:
            logger.debug("沒有封包需要處理為 .pcap")
            self.log_message("沒有封包需要處理為 .pcap")
            return
        if getattr(self, 'processing_pcap', False):
            logger.debug("已在處理 pcap，略過本次呼叫")
            return
        self.processing_pcap = True
        try:
            # 確保 .pcap 和 .csv 目錄存在且可寫
            for dir_path in [self.pcap_dir, self.csv_dir]:
                dir_abs = os.path.abspath(dir_path)
                os.makedirs(dir_abs, exist_ok=True)
                if not os.access(dir_abs, os.W_OK):
                    logger.error(f"目錄 {dir_abs} 無寫入權限")
                    self.log_message(f"目錄 {dir_abs} 無寫入權限")
                    return
                logger.debug(f"目錄 {dir_abs} 可寫")
            
            # 生成 .pcap 檔案
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = os.path.join(os.path.abspath(self.pcap_dir), f"flow_{timestamp}.pcap")
            pcap_filename = os.path.normpath(pcap_filename)
            try:
                wrpcap(pcap_filename, self.current_pcap_packets)
                logger.debug(f"已保存 {len(self.current_pcap_packets)} 個封包到 {pcap_filename}")
                self.log_message(f"已保存 {len(self.current_pcap_packets)} 個封包到 {pcap_filename}")
                self.current_pcap_packets = []  # 清空封包列表
            except Exception as e:
                logger.error(f"無法保存 PCAP 檔案 {pcap_filename}: {str(e)}")
                self.log_message(f"無法保存 PCAP 檔案 {pcap_filename}: {str(e)}")
                return
            
            # 驗證 PCAP 檔案
            if not os.path.exists(pcap_filename) or os.path.getsize(pcap_filename) == 0:
                logger.error(f"PCAP 檔案 {pcap_filename} 無效")
                self.log_message(f"PCAP 檔案 {pcap_filename} 無效")
                return
            logger.debug(f"PCAP 檔案 {pcap_filename} 創建成功，大小: {os.path.getsize(pcap_filename)} 字節")
            self.log_message(f"PCAP 檔案 {pcap_filename} 創建成功，大小: {os.path.getsize(pcap_filename)} 字節")
            
            # 執行 CICFlowMeter 轉換
            csv_dir_abs = os.path.abspath(self.csv_dir)
            cmd = f'cfm.bat "{pcap_filename}" "{csv_dir_abs}"'
            logger.debug(f"執行命令: {cmd}")
            self.log_message(f"執行命令: {cmd}")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                logger.debug(f"cfm.bat 標準輸出: {result.stdout}")
                self.log_message(f"cfm.bat 標準輸出: {result.stdout}")
                if result.stderr:
                    logger.error(f"cfm.bat 錯誤輸出: {result.stderr}")
                    self.log_message(f"cfm.bat 錯誤輸出: {result.stderr}")
                if result.returncode != 0:
                    logger.error(f"cfm.bat 執行失敗，返回碼: {result.returncode}")
                    self.log_message(f"cfm.bat 執行失敗，返回碼: {result.returncode}")
                    return
            except subprocess.TimeoutExpired:
                logger.error("cfm.bat 執行超時（60秒）")
                self.log_message("cfm.bat 執行超時（60秒）")
                return
            except Exception as e:
                logger.error(f"cfm.bat 執行失敗: {str(e)}")
                self.log_message(f"cfm.bat 執行失敗: {str(e)}")
                return
            
            # 等待 CSV 檔案生成
            timeout = 10  # 秒
            interval = 0.5
            elapsed = 0
            csv_files = []
            while elapsed < timeout:
                csv_files = [f for f in os.listdir(csv_dir_abs) if f.endswith(".csv")]
                if csv_files:
                    break
                time.sleep(interval)
                elapsed += interval
            if not csv_files:
                logger.error(f"未在 {csv_dir_abs} 中找到 CSV 檔案")
                self.log_message(f"未在 {csv_dir_abs} 中找到 CSV 檔案")
                return
            
            # 取最新 CSV
            csv_files.sort(key=lambda f: os.path.getmtime(os.path.join(csv_dir_abs, f)), reverse=True)
            csv_path = os.path.join(csv_dir_abs, csv_files[0])
            logger.debug(f"處理 CSV 檔案: {csv_path}")
            self.log_message(f"處理 CSV 檔案: {csv_path}")
            
            # 讀 CSV 並檢測
            try:
                df = pd.read_csv(csv_path, encoding='utf-8', encoding_errors='replace')
                if df.empty:
                    logger.warning(f"CSV 檔案 {csv_path} 為空")
                    self.log_message(f"CSV 檔案 {csv_path} 為空")
                    return
                logger.debug(f"CSV 檔案 {csv_path} 已載入，包含 {len(df)} 行")
                self.log_message(f"CSV 檔案 {csv_path} 已載入，包含 {len(df)} 行")
                logger.debug(f"CSV 欄位：{list(df.columns)}")  # 記錄 CSV 欄位
            except Exception as e:
                logger.error(f"無法讀取 CSV 檔案 {csv_path}: {str(e)}")
                self.log_message(f"無法讀取 CSV 檔案 {csv_path}: {str(e)}")
                return
            
            # 觸發流量預測
            for _, row in df.iterrows():
                src_ip = row.get('Src IP', '')
                dst_ip = row.get('Dst IP', '')
                proto = row.get('Protocol', '')
                features = row.to_dict()
                features['SimillarHTTP'] = 0.0
                features['Inbound'] = 1.0 if dst_ip == self.local_ip else 0.0
                flow_df = pd.DataFrame([features])
                logger.debug(f"處理流量：來源={src_ip}, 目的={dst_ip}, 特徵數={len(features)}")
                label = predict_flow(self.model, self.le, flow_df, self.training_features)
                if label:
                    proto_name = proto if isinstance(proto, str) else str(proto)
                    self.root.after(0, lambda: self.add_packet_to_table(src_ip, dst_ip, proto_name, label, features, None))
                    if label.lower() != 'benign':
                        ip_to_block = src_ip if dst_ip == (self.local_ip if self.monitor_mode.get() == "local" else self.remote_ip.get()) else dst_ip
                        if ip_to_block not in self.blocked_ips:
                            self.blocked_ips.add(ip_to_block)
                            hazard_logger.warning(
                                f"檢測到非良性流量: 標籤={label}, 來源={src_ip}, 目的={dst_ip}, 協議={proto_name}, 時間={datetime.now()}"
                            )
                            self.last_detected_ip = ip_to_block
                            self.root.after(0, lambda: self.block_button.config(state="normal"))
                            if self.auto_block.get():
                                block_ip_local(ip_to_block, self.whitelist_ips)
        finally:
            self.processing_pcap = False
class TextHandler(logging.Handler):
    """自訂日誌處理器，將日誌顯示在 tkinter Text 控件中"""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        self.text_widget.config(state='normal')
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.see(tk.END)
        self.text_widget.config(state='disabled')
        self.text_widget.update()

def main():
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
