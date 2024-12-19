import os
from scapy.all import rdpcap, RTP, UDP
from scapy.layers.inet import IP


def extract_voip_audio(pcap_file, output_audio):
    output_dir = os.path.dirname(output_audio)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Reading packets from {pcap_file}...")
    packets = rdpcap(pcap_file)

    audio_payloads = []
    for packet in packets:
        # Check for RTP packets
        if RTP in packet:
            rtp = packet[RTP]
            audio_payloads.append(bytes(rtp.payload))
        elif UDP in packet:
            udp = packet[UDP]
            if len(udp.payload) > 12:  # Minimal length for audio payloads
                audio_payloads.append(bytes(udp.payload))

    if not audio_payloads:
        print("No VoIP audio packets (RTP, UDP, etc.) found in the pcap file.")
        return

    print(f"Found {len(audio_payloads)} audio packets.")

    # Combine audio payloads
    combined_audio = b"".join(audio_payloads)

    # Save the audio payload as a raw file
    raw_audio_file = os.path.join(output_dir, "output.raw")
    with open(raw_audio_file, "wb") as f:
        f.write(combined_audio)
    print(f"Raw audio extracted to {raw_audio_file}.")

    if os.system(f"ffmpeg -f alaw -i \"{raw_audio_file}\" \"{output_audio}\"") == 0:
        print(f"Audio saved to {output_audio}.")
    else:
        print("Error: Failed to convert raw audio to WAV.")
        return

    # Cleanup
    os.remove(raw_audio_file)


pcap_file = r"sip_rtp_capture.pcapng"  
output_audio = "bin/Conversation.wav"  
extract_voip_audio(pcap_file, output_audio)
