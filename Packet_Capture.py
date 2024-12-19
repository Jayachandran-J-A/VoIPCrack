import pyshark

def capture_sip_rtp_on_invite(interface, output_file):
    print("Starting capture for SIP INVITE message...")


    sip_rtp_capture = pyshark.LiveCapture(
        interface=interface,
        output_file=output_file,
        bpf_filter="port 5060 or udp" 
    )

    invite_detected = False

    try:
        for packet in sip_rtp_capture.sniff_continuously():
            # Log SIP INVITE detection
            if not invite_detected and 'sip' in packet and hasattr(packet.sip, 'Method') and packet.sip.Method == 'INVITE':
                print("SIP INVITE detected. Capturing RTP/OPUS and continuing SIP traffic...")
                invite_detected = True

            # Stop capture on SIP BYE detection
            if 'sip' in packet and hasattr(packet.sip, 'Method') and packet.sip.Method == 'BYE':
                print("SIP BYE detected. Stopping capture...")
                break
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    finally:
        sip_rtp_capture.close()


INTERFACE = '\\Device\\NPF_{0EF304D7-D9D5-4184-8634-B92669850F39}'
#INTERFACE = 'any'
OUTPUT_FILE = 'bin/sip_rtp_capture.pcapng'


capture_sip_rtp_on_invite(interface=INTERFACE, output_file=OUTPUT_FILE)