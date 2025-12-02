from scapy.all import sniff, get_if_list, get_if_addr, Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

SECRET_KEY = b"16bytesecret1234"
BLOCK_SIZE = 16
vm_ip = "192.168.56.104"

# Auto-detect interface for the VM IP
iface = None
for i in get_if_list():
    try:
        if get_if_addr(i) == vm_ip:
            iface = i
            break
    except Exception:
        continue

if not iface:
    print("Could not find interface for IP", vm_ip)
    exit()

print(f"Sniffing TCP packets on interface: {iface}")

def packet_handler(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")

        print(f"Received payload length: {len(payload)} bytes")

        try:
            data = base64.b64decode(payload)
        except Exception as e:
            print("Base64 decode failed:", e)
            return

        iv = data[:BLOCK_SIZE]
        encrypted_data = data[BLOCK_SIZE:]

        print(f"IV length: {len(iv)} | Ciphertext length: {len(encrypted_data)}")

        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

            print("\nDecrypted file contents:\n")
            print(decrypted.decode())
        except Exception as e:
            print("AES decrypt failed:", e)

# Sniff only TCP packets on port 12345
sniff(filter="tcp port 12345", iface=iface, prn=packet_handler)
