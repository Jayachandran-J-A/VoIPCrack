import pyshark
import psutil

def capture_sip_rtp_on_invite(interface, output_file):
    print("Starting capture for SIP INVITE message...")

    # Create a live capture object using pyshark
    sip_rtp_capture = pyshark.LiveCapture(
        interface=interface,
        output_file=output_file,
        bpf_filter="port 5060 or udp"  # BPF filter for SIP (5060) and RTP (UDP)
    )

    invite_detected = False

    try:
        for packet in sip_rtp_capture.sniff_continuously():
            # Detect SIP INVITE packet
            if not invite_detected and 'sip' in packet and hasattr(packet.sip, 'Method') and packet.sip.Method == 'INVITE':
                print("SIP INVITE detected. Capturing RTP/OPUS and continuing SIP traffic...")
                invite_detected = True

            # Stop capture if SIP BYE is detected
            if 'sip' in packet and hasattr(packet.sip, 'Method') and packet.sip.Method == 'BYE':
                print("SIP BYE detected. Stopping capture...")
                break
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    finally:
        sip_rtp_capture.close()


def list_interfaces():
    interfaces = []
    print("\nAvailable Network Interfaces:")
    for idx, (name, addrs) in enumerate(psutil.net_if_addrs().items()):
        print(f"{idx + 1}. {name}")
        interfaces.append(name)
    
    return interfaces

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

if __name__ == "__main__":
    # Step 1: Select the network interface dynamically
    interface = select_interface()
    output_file = 'sip_rtp_capture.pcapng'  # Output file for the capture

    capture_sip_rtp_on_invite(interface=interface, output_file=output_file)
