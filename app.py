from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import pandas as pd
import joblib
import random
import time
from threading import Thread

app = Flask(__name__)

# Load your pre-trained model
try:
    model = joblib.load("model.pkl")
except:
    print("CRITICAL: model.pkl not found. Ensure training is complete.")

# Storage for live tracking
packet_data = []
attack_stats = {"times": [], "attacks": [], "normal": []}
flow_stats = {}

def classify_attack(features, proto, packet):
    """
    Categorizes the attack based on traffic features and payload.
    """
    # 1. SQL Injection Detection (Checking Payload)
    if packet.haslayer(Raw):
        try:
            payload = str(packet[Raw].load).lower()
            sqli_keywords = ["' or 1=1", "--", "union select", "drop table", "select * from"]
            if any(k in payload for k in sqli_keywords):
                return "SQL INJECTION"
        except:
            pass

    # 2. DDoS (Based on PPS rate)
    if features['rate'].iloc[0] > 50: 
        return "DDoS" 
    
    # 3. Brute Force (Based on Source Load)
    elif features['sload'].iloc[0] > 100000: 
        return "BRUTE FORCE"
        
    # 4. MITM (Protocol Anomalies)
    elif proto == "other":
        return "MITM (ARP Spoof)"
        
    return "SUSPICIOUS ACTIVITY"

def process_packet(packet):
    try:
        if IP not in packet: return
        ip = packet[IP]
        proto = "tcp" if TCP in packet else "udp" if UDP in packet else "other"

        flow_id = (ip.src, ip.dst, proto)
        now = time.time()
        
        if flow_id not in flow_stats:
            flow_stats[flow_id] = {"start": now, "sbytes": 0, "dbytes": 0, "spkts": 0, "dpkts": 0}

        flow = flow_stats[flow_id]
        flow["sbytes"] += len(packet)
        flow["spkts"] += 1
        duration = max(now - flow["start"], 0.001)

        # Feature mapping for XGBoost
        features = pd.DataFrame([{
            "sbytes": flow["sbytes"], "dbytes": flow["dbytes"],
            "spkts": flow["spkts"], "dpkts": flow["dpkts"],
            "rate": flow["spkts"] / duration, "sttl": ip.ttl, "dttl": ip.ttl,
            "sload": flow["sbytes"] / duration, "dload": flow["dbytes"] / duration,
            "smean": flow["sbytes"] / max(flow["spkts"], 1), "dmean": 0
        }])

        # Predict using model confidence
        try:
            prob = model.predict_proba(features)[0][1]
        except:
            prob = 0.0 # Default if model fails

        if prob >= 0.9:
            status = classify_attack(features, proto, packet) # Refine label
        else:
            status = "NORMAL"

        current_time = datetime.now().strftime("%H:%M:%S")
        packet_data.append({
            "time": current_time, "src": ip.src, "dst": ip.dst, "status": status,
            "lat": random.uniform(-60, 60), "lon": random.uniform(-180, 180)
        })

        # Stats for charts
        attack_count = sum(1 for p in packet_data if p["status"] != "NORMAL")
        normal_count = sum(1 for p in packet_data if p["status"] == "NORMAL")
        attack_stats["times"].append(current_time)
        attack_stats["attacks"].append(attack_count)
        attack_stats["normal"].append(normal_count)

        if len(attack_stats["times"]) > 20:
            for key in attack_stats: attack_stats[key].pop(0)
        if len(packet_data) > 30: packet_data.pop(0)

    except Exception as e:
        print(f"Error: {e}")

def start_sniffing():
    sniff(prn=process_packet, store=False)

@app.route("/")
def index(): return render_template("index.html")

@app.route("/packets")
def packets(): return jsonify(packet_data)

@app.route("/stats")
def stats(): return jsonify(attack_stats)

if __name__ == "__main__":
    Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True, use_reloader=False)