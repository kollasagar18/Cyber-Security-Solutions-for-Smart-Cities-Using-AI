import scapy.all as scapy
import threading
import time
import os
import joblib
import pandas as pd
from collections import defaultdict
from scapy.all import IP
from sklearn.ensemble import IsolationForest

# File paths
DATA_FILE = "network_traffic.csv"
MODEL_FILE = "cyber_model.pkl"
LOG_FILE = "attack_logs.txt"

# Thresholds
TIME_WINDOW = 10
ATTACK_THRESHOLD = 10
BLOCK_THRESHOLD = 15

ip_packet_data = defaultdict(list)
COMMON_PROTOCOLS = [0, 1, 2, 6, 17, 47, 50, 51, 88, 89, 115, 80, 8080]

model = None
INTERFACE = "Software Loopback Interface 1"  # Change this if needed

def log_attack(src_ip, dst_ip, message):
    log_message = f"{time.ctime()} - {message} | From: {src_ip} → To: {dst_ip}"
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(log_message + "\n")
    print(log_message)

def capture_network_data(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        protocol = packet.proto
        ttl = packet[IP].ttl

        file_exists = os.path.exists(DATA_FILE)
        with open(DATA_FILE, "a") as file:
            if not file_exists:
                file.write("PacketSize,Protocol,TTL,SrcIP,DstIP\n")
            file.write(f"{packet_size},{protocol},{ttl},{src_ip},{dst_ip}\n")

def train_model():
    if not os.path.exists(DATA_FILE):
        print("🚫 No network data available for training.")
        return

    df = pd.read_csv(DATA_FILE)
    print("[DEBUG] Sample training data:")
    print(df.head())

    try:
        df["SrcIP"] = df["SrcIP"].apply(lambda ip: sum(int(x) << (8 * i) for i, x in enumerate(reversed(ip.split(".")))))
        df["DstIP"] = df["DstIP"].apply(lambda ip: sum(int(x) << (8 * i) for i, x in enumerate(reversed(ip.split(".")))))
        model_instance = IsolationForest(contamination=0.1)
        model_instance.fit(df)

        if isinstance(model_instance, IsolationForest):
            joblib.dump(model_instance, MODEL_FILE)
            print("✅ Model trained and saved!")
        else:
            print("🚫 Training did not produce a valid model")

    except Exception as e:
        print(f"❌ Training failed: {e}")

def detect_attack(packet):
    global model
    if packet.haslayer(IP):
        if not model:
            print("🚫 Model not available, skipping packet...")
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        protocol = packet.proto
        ttl = packet[IP].ttl
        current_time = time.time()

        ip_packet_data[src_ip].append(current_time)
        ip_packet_data[src_ip] = [t for t in ip_packet_data[src_ip] if current_time - t <= TIME_WINDOW]

        data = pd.DataFrame([[packet_size, protocol, ttl,
                              sum(int(x) << (8 * i) for i, x in enumerate(reversed(src_ip.split(".")))),
                              sum(int(x) << (8 * i) for i, x in enumerate(reversed(dst_ip.split("."))))]],
                            columns=["PacketSize", "Protocol", "TTL", "SrcIP", "DstIP"])

        prediction = model.predict(data)

        if protocol not in COMMON_PROTOCOLS:
            log_attack(src_ip, dst_ip, "❌ Uncommon Protocol detected!")

        if prediction[0] == -1:
            if ttl < 10 or ttl > 200:
                log_attack(src_ip, dst_ip, "⚠ Malware Attack detected!")
            if len(ip_packet_data[src_ip]) > BLOCK_THRESHOLD:
                log_attack(src_ip, dst_ip, "🚨 DDoS Attack detected!")
            else:
                log_attack(src_ip, dst_ip, "🔴 Suspicious activity detected!")

# Start program
if _name_ == "_main_":
    # Step 1: Capture normal traffic for 30 seconds
    print("⏳ Capturing network traffic for training (30s)...")
    scapy.sniff(iface=INTERFACE, prn=capture_network_data, store=False, timeout=30)

    # Step 2: Train model
    train_model()

    # Step 3: Load model safely
    if os.path.exists(MODEL_FILE):
        loaded = joblib.load(MODEL_FILE)
        if hasattr(loaded, "predict"):
            model = loaded
            print(f"✅ Model loaded successfully: {type(model)}")
        else:
            print("⚠ Loaded model is not valid!")
    else:
        print("🚫 Model file not found after training.")

    # Step 4: Start live detection
    if model:
        print("🔍 Monitoring network for cyber threats...")
        scapy.sniff(iface=INTERFACE, prn=detect_attack, store=False)
